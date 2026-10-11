package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type providerFixture struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	mu       sync.Mutex
	keys     []jose.JSONWebKey
	requests atomic.Int32
	verifier *Verifier
}

func newProvider(t *testing.T) *providerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &providerFixture{key: key, keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "first", Algorithm: "RS256", Use: "sig"}}}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(writer).Encode(map[string]any{"issuer": fixture.server.URL, "jwks_uri": fixture.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}, "authorization_endpoint": fixture.server.URL + "/authorize", "token_endpoint": fixture.server.URL + "/token", "userinfo_endpoint": fixture.server.URL + "/userinfo", "end_session_endpoint": fixture.server.URL + "/logout", "backchannel_logout_supported": true})
		case "/keys":
			fixture.requests.Add(1)
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: fixture.keys})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(fixture.server.Close)
	fixture.verifier, err = New(context.Background(), Config{Issuer: fixture.server.URL, ClientID: "app", httpClient: fixture.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *providerFixture) claims() map[string]any {
	return map[string]any{"iss": fixture.server.URL, "aud": "app", "sub": "person-123", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "email": "person@example.com", "groups": []string{"operators"}, "roles": []string{"external-role"}}
}

func sign(t *testing.T, key *rsa.PrivateKey, keyID, tokenType string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: keyID}}, (&jose.SignerOptions{}).WithType(jose.ContentType(tokenType)))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAuthenticate(t *testing.T) {
	fixture := newProvider(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		change    func(map[string]any)
		tokenType string
		key       *rsa.PrivateKey
		raw       string
		want      error
	}{
		{name: "valid"},
		{name: "invalid signature", key: otherKey, want: errInvalidToken},
		{name: "expired", change: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, want: errInvalidToken},
		{name: "wrong issuer", change: func(c map[string]any) { c["iss"] = "https://wrong.example" }, want: errInvalidToken},
		{name: "wrong audience", change: func(c map[string]any) { c["aud"] = "wrong" }, want: errInvalidToken},
		{name: "audience list", change: func(c map[string]any) { c["aud"] = []string{"other", "app"} }},
		{name: "missing subject", change: func(c map[string]any) { delete(c, "sub") }, want: errInvalidToken},
		{name: "missing expiration", change: func(c map[string]any) { delete(c, "exp") }, want: errInvalidToken},
		{name: "missing issued at", change: func(c map[string]any) { delete(c, "iat") }, want: errInvalidToken},
		{name: "future issued at", change: func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }, want: errInvalidToken},
		{name: "future not before", change: func(c map[string]any) { c["nbf"] = time.Now().Add(time.Minute).Unix() }, want: errInvalidToken},
		{name: "malformed", raw: "not.a.token", want: errInvalidToken},
		{name: "ID token rejected", tokenType: "JWT", want: errInvalidToken},
		{name: "refresh token rejected", tokenType: "refresh+jwt", want: errInvalidToken},
		{name: "logout event rejected", change: func(c map[string]any) { c["events"] = map[string]any{logoutEventType: map[string]any{}} }, want: errInvalidToken},
		{name: "malformed groups", change: func(c map[string]any) { c["groups"] = "operators" }, want: errInvalidToken},
		{name: "malformed roles", change: func(c map[string]any) { c["roles"] = []int{1} }, want: errInvalidToken},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.claims()
			if test.change != nil {
				test.change(claims)
			}
			key := test.key
			if key == nil {
				key = fixture.key
			}
			typ := test.tokenType
			if typ == "" {
				typ = "at+jwt"
			}
			raw := test.raw
			if raw == "" {
				raw = sign(t, key, "first", typ, claims)
			}
			actor, err := fixture.verifier.authenticate(context.Background(), raw)
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if test.want == nil && (actor.Subject != "person-123" || actor.Email != "person@example.com" || len(actor.Groups) != 1 || actor.Groups[0] != "operators" || len(actor.Roles) != 1 || actor.Roles[0] != "external-role") {
				t.Fatalf("claims not extracted: %+v", actor)
			}
		})
	}
	claims := fixture.claims()
	delete(claims, "email")
	delete(claims, "groups")
	delete(claims, "roles")
	if _, err := fixture.verifier.authenticate(context.Background(), sign(t, fixture.key, "first", "at+jwt", claims)); err != nil {
		t.Fatal(err)
	}
}

func TestRequestAndContext(t *testing.T) {
	fixture := newProvider(t)
	raw := sign(t, fixture.key, "first", "at+jwt", fixture.claims())
	for _, test := range []struct {
		header string
		want   error
	}{{"", errInvalidToken}, {"Basic secret", errInvalidToken}, {"Bearer", errInvalidToken}, {"Bearer one two", errInvalidToken}, {"bEaReR " + raw, nil}} {
		request := httptest.NewRequest("GET", "/api/me", nil)
		if test.header != "" {
			request.Header.Set("Authorization", test.header)
		}
		_, err := fixture.verifier.authenticateRequest(request)
		if !errors.Is(err, test.want) {
			t.Fatalf("got %v want %v", err, test.want)
		}
		called := false
		handler := fixture.verifier.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			called = true
			actor, ok := FromContext(request.Context())
			if !ok || actor.Subject != "person-123" {
				t.Error("missing context identity")
			}
			writer.WriteHeader(204)
		}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if called != (test.want == nil) {
			t.Fatal("middleware boundary failed")
		}
		if !called && (response.Code != 401 || response.Header().Get("WWW-Authenticate") != "Bearer") {
			t.Fatal("missing challenge")
		}
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Add("Authorization", "Bearer "+raw)
	request.Header.Add("Authorization", "Bearer "+raw)
	if _, err := fixture.verifier.authenticateRequest(request); !errors.Is(err, errInvalidToken) {
		t.Fatal("duplicate credentials accepted")
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("anonymous context authenticated")
	}
	actor := Identity{Subject: "one", Groups: []string{"original"}}
	ctx := WithContext(context.Background(), actor)
	actor.Groups[0] = "mutated"
	copyActor, _ := FromContext(ctx)
	copyActor.Groups[0] = "again"
	original, _ := FromContext(ctx)
	if original.Groups[0] != "original" {
		t.Fatal("context claims are mutable")
	}
}

func TestJWKSCacheAndRotation(t *testing.T) {
	fixture := newProvider(t)
	raw := sign(t, fixture.key, "first", "at+jwt", fixture.claims())
	for range 3 {
		if _, err := fixture.verifier.authenticate(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.requests.Load() != 1 {
		t.Fatalf("expected cached keys, requests=%d", fixture.requests.Load())
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.keys = []jose.JSONWebKey{{Key: &rotated.PublicKey, KeyID: "second", Algorithm: "RS256", Use: "sig"}}
	fixture.mu.Unlock()
	newRaw := sign(t, rotated, "second", "at+jwt", fixture.claims())
	for range 2 {
		if _, err := fixture.verifier.authenticate(context.Background(), newRaw); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.requests.Load() != 2 {
		t.Fatalf("expected one rotation fetch, requests=%d", fixture.requests.Load())
	}
}

func TestLogoutValidation(t *testing.T) {
	fixture := newProvider(t)
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"valid", nil, true}, {"optional exp", func(c map[string]any) { delete(c, "exp") }, true},
		{"sid only", func(c map[string]any) { delete(c, "sub"); c["sid"] = "session" }, true},
		{"no subject or sid", func(c map[string]any) { delete(c, "sub") }, false},
		{"no jti", func(c map[string]any) { delete(c, "jti") }, false},
		{"no iat", func(c map[string]any) { delete(c, "iat") }, false},
		{"old iat", func(c map[string]any) { c["iat"] = time.Now().Add(-6 * time.Minute).Unix() }, false},
		{"future iat", func(c map[string]any) { c["iat"] = time.Now().Add(time.Minute).Unix() }, false},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, false},
		{"nonce", func(c map[string]any) { c["nonce"] = "" }, false},
		{"null nonce", func(c map[string]any) { c["nonce"] = nil }, false},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://other.example" }, false},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other" }, false},
		{"missing event", func(c map[string]any) { delete(c, "events") }, false},
		{"null event", func(c map[string]any) { c["events"] = map[string]any{logoutEventType: nil} }, false},
		{"nonempty event", func(c map[string]any) { c["events"] = map[string]any{logoutEventType: map[string]any{"bad": true}} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.claims()
			claims["jti"] = "event-1"
			claims["events"] = map[string]any{logoutEventType: map[string]any{}}
			if test.change != nil {
				test.change(claims)
			}
			raw := sign(t, fixture.key, "first", "JWT", claims)
			event, err := fixture.verifier.validateLogout(context.Background(), raw)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
			if test.valid && event.TokenID != "event-1" {
				t.Fatal("missing event ID")
			}
		})
	}
	if _, err := fixture.verifier.validateLogout(context.Background(), "bad"); err == nil {
		t.Fatal("malformed logout accepted")
	}
}

func TestLogoutHandler(t *testing.T) {
	fixture := newProvider(t)
	claims := fixture.claims()
	claims["jti"] = "once"
	claims["events"] = map[string]any{logoutEventType: map[string]any{}}
	raw := sign(t, fixture.key, "first", "JWT", claims)
	processed := map[string]bool{}
	calls := 0
	handler := fixture.verifier.logoutHandler(func(_ context.Context, event logoutEvent) error {
		if !processed[event.TokenID] {
			processed[event.TokenID] = true
			calls++
		}
		return nil
	})
	for range 2 {
		request := httptest.NewRequest("POST", "/auth/logout", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 200 {
			t.Fatalf("status %d", response.Code)
		}
	}
	if calls != 1 {
		t.Fatal("application replay protection failed")
	}
	for _, test := range []struct {
		method, body string
		status       int
	}{{"GET", "", 405}, {"POST", "logout_token=bad", 400}, {"POST", "", 400}, {"POST", "logout_token=one&logout_token=two", 400}} {
		request := httptest.NewRequest(test.method, "/auth/logout", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("got %d want %d", response.Code, test.status)
		}
	}
	if calls != 1 {
		t.Fatal("invalid logout reached application")
	}
}

func TestConfiguration(t *testing.T) {
	for _, config := range []Config{{}, {Issuer: "http://localhost", ClientID: "app"}, {Issuer: "https://example.com"}, {Issuer: "https://user:secret@example.com", ClientID: "app"}} {
		if _, err := New(context.Background(), config); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}
