// AppKit's browser-session security tests.
package identity_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/realtime"
	"github.com/coder/websocket"
	jose "github.com/go-jose/go-jose/v4"
)

type loginAttempt struct {
	query      url.Values
	cookie     *http.Cookie
	claims     map[string]any
	access, id string
}
type sessionFixture struct {
	t             *testing.T
	provider, app *httptest.Server
	key           *rsa.PrivateKey
	signer        jose.Signer
	mu            sync.Mutex
	codes         map[string]*loginAttempt
	sessions      *identity.Sessions
	config        identity.SessionConfig
	hub           realtime.Hub
	gate, release chan struct{}
}

func newSessionFixture(t *testing.T, lifetime time.Duration, secret string) *sessionFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	f := &sessionFixture{t: t, signer: signer, key: key, codes: map[string]*loginAttempt{}}
	f.provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": f.provider.URL, "authorization_endpoint": f.provider.URL + "/authorize", "token_endpoint": f.provider.URL + "/token", "jwks_uri": f.provider.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}, "backchannel_logout_supported": true})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			r.ParseForm()
			f.mu.Lock()
			attempt := f.codes[r.Form.Get("code")]
			gate, release := f.gate, f.release
			f.mu.Unlock()
			if attempt == nil {
				http.Error(w, "unknown code", 400)
				return
			}
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("client_id") != "appkit" || r.Form.Get("client_secret") != secret || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != f.app.URL+"/auth/callback" || base64.RawURLEncoding.EncodeToString(challenge[:]) != attempt.query.Get("code_challenge") {
				http.Error(w, "bad exchange", 400)
				return
			}
			if gate != nil {
				close(gate)
				<-release
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": attempt.access, "id_token": attempt.id, "token_type": "Bearer", "expires_in": 32400, "refresh_token": "fixture-refresh-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	policy, _ := authz.New(map[string][]string{"observer": {"diagnostics.read"}}, map[string][]string{"observers": {"observer"}}, nil, nil)
	f.app = httptest.NewServer(nil)
	f.config = identity.SessionConfig{Issuer: f.provider.URL, ClientID: "appkit", ClientSecret: secret, Origin: f.app.URL, DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy, Lifetime: lifetime}
	f.open()
	t.Cleanup(func() { f.hub.Close(); f.sessions.Close(); f.app.Close(); f.provider.Close() })
	return f
}
func (f *sessionFixture) open() {
	f.t.Helper()
	s, err := identity.NewSessions(context.Background(), f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	f.sessions = s
	router := s.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit, ClientAddress: mustClientAddress(f.t, "remote")})
	who := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, _ := identity.FromContext(r.Context())
		deadline, _ := r.Context().Deadline()
		json.NewEncoder(w).Encode(map[string]any{"subject": a.Subject, "deadline": deadline.UnixMilli(), "permissions": a.Permissions, "can": a.Can("diagnostics.read")})
	})
	router.Private("GET /protected", "diagnostics.read", who)
	router.Private("POST /protected", "diagnostics.read", who)
	router.Service("GET /bearer", "diagnostics.read", who)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	router.Private("GET /diagnostics", "diagnostics.read", ok)
	router.Private("GET /notes", "notes.write", ok)
	router.Private("POST /mutate", "diagnostics.read", ok)
	router.Private("GET /socket", "diagnostics.read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := f.hub.Accept(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			if _, err = c.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	f.app.Config.Handler = router // No requests run while replacing the stopped handler.
}
func (f *sessionFixture) request(method, path string, cookie *http.Cookie, headers map[string]string, body string) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.app.URL+path, strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}
func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func status(t *testing.T, r *http.Response, want int) string {
	t.Helper()
	body := readBody(t, r)
	if r.StatusCode != want {
		t.Fatalf("status %d, want %d: %s", r.StatusCode, want, body)
	}
	return body
}
func (f *sessionFixture) sign(claims map[string]any) string {
	f.t.Helper()
	b, _ := json.Marshal(claims)
	sig, err := f.signer.Sign(b)
	if err != nil {
		f.t.Fatal(err)
	}
	s, err := sig.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}
func (f *sessionFixture) begin(sid string, edit func(map[string]any)) *loginAttempt {
	f.t.Helper()
	res := f.request("GET", "/auth/login?next=%2Fprotected", nil, nil, "")
	status(f.t, res, 303)
	u, _ := url.Parse(res.Header.Get("Location"))
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("prompt") != "" || q.Get("scope") != "openid email groups" {
		f.t.Fatal("missing secure login parameters")
	}
	now := time.Now().Unix()
	a := &loginAttempt{query: q, access: "fixture-access-token"}
	h := sha256.Sum256([]byte(a.access))
	a.claims = map[string]any{"iss": f.provider.URL, "aud": "appkit", "sub": "alice", "sid": sid, "iat": now, "exp": now + 32400, "nonce": q.Get("nonce"), "email": "alice@example.test", "groups": []string{"observers"}, "at_hash": base64.RawURLEncoding.EncodeToString(h[:16])}
	if edit != nil {
		edit(a.claims)
	}
	a.id = f.sign(a.claims)
	for _, c := range res.Cookies() {
		if strings.HasSuffix(c.Name, "_login") {
			a.cookie = c
		}
	}
	if a.cookie == nil || !a.cookie.HttpOnly || a.cookie.SameSite != http.SameSiteLaxMode {
		f.t.Fatal("missing login cookie protections")
	}
	f.mu.Lock()
	f.codes[q.Get("state")] = a
	f.mu.Unlock()
	return a
}
func (f *sessionFixture) finish(a *loginAttempt) *http.Response {
	return f.request("GET", "/auth/callback?"+url.Values{"state": {a.query.Get("state")}, "code": {a.query.Get("state")}}.Encode(), a.cookie, nil, "")
}
func (f *sessionFixture) login(sid string) (*http.Cookie, *loginAttempt) {
	f.t.Helper()
	a := f.begin(sid, nil)
	res := f.finish(a)
	status(f.t, res, 303)
	for _, c := range res.Cookies() {
		if c.Name == "appkit_local" {
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
				f.t.Fatal("bad session cookie")
			}
			return c, a
		}
	}
	f.t.Fatal("missing session cookie")
	return nil, nil
}
func (f *sessionFixture) backchannel(sid, subject, jti string) {
	f.t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{"iss": f.provider.URL, "aud": "appkit", "iat": now, "exp": now + 60, "jti": jti, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
	if sid != "" {
		claims["sid"] = sid
	}
	if subject != "" {
		claims["sub"] = subject
	}
	token := f.sign(claims)
	status(f.t, f.request("POST", "/auth/backchannel", nil, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, url.Values{"logout_token": {token}}.Encode()), 200)
}
func (f *sessionFixture) socket(cookie *http.Cookie, origin string) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	h := http.Header{"Cookie": {cookie.String()}}
	if origin != "" {
		h.Set("Origin", origin)
	}
	return websocket.Dial(ctx, strings.Replace(f.app.URL, "http:", "ws:", 1)+"/socket", &websocket.DialOptions{HTTPHeader: h})
}
func mustClose(t *testing.T, c *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := c.Read(ctx)
	if err == nil || ctx.Err() != nil {
		t.Fatal("revoked socket did not close immediately")
	}
}

func TestSessionPersistenceAndIsolation(t *testing.T) {
	f := newSessionFixture(t, 0, "")
	cookie, a := f.login("sid-one")
	before := status(t, f.request("GET", "/protected", cookie, nil, ""), 200)
	body := status(t, f.request("GET", "/auth/session", cookie, nil, ""), 200)
	if !strings.Contains(body, "diagnostics.read") || strings.Contains(body, a.id) || strings.Contains(body, cookie.Value) {
		t.Fatal("session endpoint permissions or token exposure")
	}
	var who struct{ Deadline int64 }
	json.Unmarshal([]byte(before), &who)
	if d := time.Until(time.UnixMilli(who.Deadline)); d < 8*time.Hour-time.Minute || d > 8*time.Hour {
		t.Fatalf("default lifetime %v", d)
	}
	// Check a different process, not merely a second connection in this process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestSessionSecondProcess$")
	cmd.Env = append(os.Environ(), "APPKIT_LOCK_TEST=1", "APPKIT_LOCK_DB="+f.config.DatabasePath, "APPKIT_LOCK_ISSUER="+f.provider.URL, "APPKIT_LOCK_ORIGIN="+f.app.URL)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("process lock: %v %s", err, output)
	}
	f.sessions.Close()
	f.open()
	after := status(t, f.request("GET", "/protected", cookie, nil, ""), 200)
	if after != before {
		t.Fatal("restart/activity changed identity or expiry")
	}
	f.sessions.Close()
	bytes, err := os.ReadFile(f.config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{cookie.Value, a.id, a.access, "fixture-refresh-token"} {
		if strings.Contains(string(bytes), secret) {
			t.Fatal("raw credential persisted")
		}
	}
	f.open()
	// Sign-out ends the app session before it returns.
	status(t, f.request("POST", "/auth/logout", cookie, map[string]string{"Origin": f.app.URL}, ""), 303)
	status(t, f.request("GET", "/protected", cookie, nil, ""), 401)
}
func TestSessionSecondProcess(t *testing.T) {
	if os.Getenv("APPKIT_LOCK_TEST") != "1" {
		return
	}
	policy, _ := authz.New(nil, nil, nil, nil)
	s, err := identity.NewSessions(context.Background(), identity.SessionConfig{Issuer: os.Getenv("APPKIT_LOCK_ISSUER"), ClientID: "appkit", Origin: os.Getenv("APPKIT_LOCK_ORIGIN"), DatabasePath: os.Getenv("APPKIT_LOCK_DB"), Policy: policy})
	if s != nil {
		s.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "exclusively") {
		t.Fatalf("expected clear process-lock failure, got %v", err)
	}
}
func TestSessionLoginValidation(t *testing.T) {
	f := newSessionFixture(t, 0, "fixture-client-secret")
	for name, edit := range map[string]func(map[string]any){
		"nonce": func(c map[string]any) { c["nonce"] = "wrong" }, "subject": func(c map[string]any) { delete(c, "sub") }, "sid": func(c map[string]any) { delete(c, "sid") }, "audience": func(c map[string]any) { c["aud"] = "other" }, "issuer": func(c map[string]any) { c["iss"] = "https://wrong.example" }, "binding": func(c map[string]any) { c["at_hash"] = "wrong" }, "expired": func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, "authorized party": func(c map[string]any) { c["azp"] = "other" }, "groups": func(c map[string]any) { c["groups"] = "observers" },
	} {
		t.Run(name, func(t *testing.T) { a := f.begin("validation", edit); status(t, f.finish(a), 502) })
	}
	// A person with none of the application's groups gets no session.
	noRole := f.begin("no-role", func(c map[string]any) { c["groups"] = []string{"strangers"} })
	if response := f.finish(noRole); response.StatusCode != 403 || len(response.Cookies()) > 1 {
		t.Fatalf("no role: status %d, cookies %v", response.StatusCode, response.Cookies())
	}
	a := f.begin("valid", nil)
	status(t, f.request("GET", "/auth/callback?state="+a.query.Get("state")+"&code=x", nil, nil, ""), 400)
	wrong := *a.cookie
	wrong.Value = "wrong"
	status(t, f.request("GET", "/auth/callback?state="+a.query.Get("state")+"&code=x", &wrong, nil, ""), 400)
	status(t, f.finish(a), 303)
	status(t, f.finish(a), 400)
	// A signed-out page request gets the JSON 401, never a redirect to sign-in.
	if body := status(t, f.request("GET", "/protected", nil, map[string]string{"Accept": "text/html"}, ""), 401); body != "{\"error\":\"Sign in required.\"}\n" {
		t.Fatalf("signed-out page body %q", body)
	}
}
func TestSessionCSRFAndCredentialBoundaries(t *testing.T) {
	f := newSessionFixture(t, 0, "")
	cookie, _ := f.login("csrf")
	for _, headers := range []map[string]string{nil, {"Origin": "https://evil.example"}, {"Origin": f.app.URL, "Sec-Fetch-Site": "same-site"}, {"Origin": "null"}} {
		status(t, f.request("POST", "/protected", cookie, headers, ""), 403)
		status(t, f.request("POST", "/auth/logout", cookie, headers, ""), 403)
	}
	status(t, f.request("POST", "/protected", cookie, map[string]string{"Origin": f.app.URL}, ""), 200)
	status(t, f.request("GET", "/bearer", cookie, nil, ""), 401)
	status(t, f.request("GET", "/protected", nil, map[string]string{"Authorization": "Bearer fixture"}, ""), 401)
	for _, origin := range []string{"", "https://evil.example"} {
		c, res, err := f.socket(cookie, origin)
		if c != nil {
			c.CloseNow()
		}
		if err == nil || res.StatusCode != 403 {
			t.Fatal("cross-site websocket accepted")
		}
	}
	// A service route verifies a Rauthy access token on its own.
	now := time.Now().Unix()
	claims := map[string]any{"iss": f.provider.URL, "aud": "appkit", "sub": "alice", "iat": now, "exp": now + 60, "groups": []string{"observers"}}
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "fixture"))
	payload, _ := json.Marshal(claims)
	signed, _ := signer.Sign(payload)
	token, _ := signed.CompactSerialize()
	status(t, f.request("GET", "/bearer", nil, map[string]string{"Authorization": "Bearer " + token}, ""), 200)
	f.backchannel("", "alice", "bearer-logout")
	status(t, f.request("GET", "/bearer", nil, map[string]string{"Authorization": "Bearer " + token}, ""), 200)
}
func TestSessionBackchannelAndRace(t *testing.T) {
	f := newSessionFixture(t, 0, "")
	one, _ := f.login("one")
	two, _ := f.login("two")
	c, _, err := f.socket(one, f.app.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	f.backchannel("one", "", "logout-one")
	mustClose(t, c)
	status(t, f.request("GET", "/protected", one, nil, ""), 401)
	status(t, f.request("GET", "/protected", two, nil, ""), 200)
	f.backchannel("one", "", "logout-one")
	f.backchannel("", "alice", "logout-all")
	status(t, f.request("GET", "/protected", two, nil, ""), 401)
	status(t, f.request("POST", "/auth/backchannel", nil, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "logout_token=unsigned"), 400)
	for _, subjectWide := range []bool{false, true} {
		a := f.begin(fmt.Sprint("racing", subjectWide), nil)
		f.mu.Lock()
		f.gate = make(chan struct{})
		f.release = make(chan struct{})
		gate, release := f.gate, f.release
		f.mu.Unlock()
		result := make(chan *http.Response, 1)
		go func() { result <- f.finish(a) }()
		<-gate
		sid, subject := a.claims["sid"].(string), ""
		if subjectWide {
			sid = ""
			subject = "alice"
		}
		f.backchannel(sid, subject, fmt.Sprint("race-", subjectWide))
		close(release)
		status(t, <-result, 401)
		f.mu.Lock()
		f.gate = nil
		f.release = nil
		f.mu.Unlock()
	}
	// Durable tombstones also reject callbacks after the app restarts.
	f.backchannel("after-restart", "", "durable")
	f.sessions.Close()
	f.open()
	a := f.begin("after-restart", nil)
	status(t, f.finish(a), 401)
}
func TestSessionExpiryAndEvents(t *testing.T) {
	f := newSessionFixture(t, time.Second, "")
	cookie, _ := f.login("short")
	c, _, err := f.socket(cookie, f.app.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	response := f.request("GET", "/auth/events", cookie, nil, "")
	events := readBody(t, response)
	if !strings.Contains(events, "event: ready") || !strings.Contains(events, "event: signed-out") {
		t.Fatal("missing expiry notification")
	}
	mustClose(t, c)
	status(t, f.request("GET", "/protected", cookie, nil, ""), 401)
}

func TestSessionOnSessionRequest(t *testing.T) {
	f := newSessionFixture(t, 0, "")
	f.sessions.Close()
	f.config.OnSessionRequest = func(r *http.Request, actor identity.Identity) (any, error) {
		if actor.Subject == "" {
			t.Fatal("app info called without an identity")
		}
		return map[string]string{"display_name": "Person " + actor.Subject}, nil
	}
	f.open()
	cookie, _ := f.login("sid-one")
	if body := status(t, f.request("GET", "/auth/session", cookie, nil, ""), 200); !strings.Contains(body, `"app":{"display_name":"Person `) {
		t.Fatalf("app info missing: %s", body)
	}
	if body := status(t, f.request("GET", "/auth/session", nil, nil, ""), 200); strings.Contains(body, "app") {
		t.Fatalf("app info while signed out: %s", body)
	}
	f.sessions.Close()
	f.config.OnSessionRequest = func(*http.Request, identity.Identity) (any, error) { return nil, errors.New("down") }
	f.open()
	status(t, f.request("GET", "/auth/session", cookie, nil, ""), 503)
}

// TestSessionPermissions checks that cookie sessions and bearer tokens arrive
// with the permissions their groups grant, and that none are stored.
func TestSessionPermissions(t *testing.T) {
	f := newSessionFixture(t, 0, "")
	cookie, _ := f.login("permissions")
	var who struct {
		Permissions []string
		Can         bool
	}
	json.Unmarshal([]byte(status(t, f.request("GET", "/protected", cookie, nil, ""), 200)), &who)
	if !who.Can || strings.Join(who.Permissions, ",") != "diagnostics.read" {
		t.Fatalf("cookie session permissions %v", who)
	}
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "fixture"))
	bearer := func(groups []string) string {
		now := time.Now().Unix()
		payload, _ := json.Marshal(map[string]any{"iss": f.provider.URL, "aud": "appkit", "sub": "alice", "iat": now, "exp": now + 60, "groups": groups})
		signed, _ := signer.Sign(payload)
		token, _ := signed.CompactSerialize()
		return token
	}
	json.Unmarshal([]byte(status(t, f.request("GET", "/bearer", nil, map[string]string{"Authorization": "Bearer " + bearer([]string{"observers"})}, ""), 200)), &who)
	if !who.Can || strings.Join(who.Permissions, ",") != "diagnostics.read" {
		t.Fatalf("bearer permissions %v", who)
	}
	// An unknown group grants nothing, so the route's permission refuses it.
	status(t, f.request("GET", "/bearer", nil, map[string]string{"Authorization": "Bearer " + bearer([]string{"strangers"})}, ""), 403)
	f.sessions.Close()
	stored, err := os.ReadFile(f.config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "diagnostics.read") {
		t.Fatal("permissions were stored with the session")
	}
	f.open()
}
