// Package identitytest provides a local fake Rauthy for application tests, so
// sign-in, sessions, CSRF, and bearer routes can be tested without a live provider.
package identitytest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is the person the fake provider signs in.
type User struct {
	Subject string
	Email   string
	Groups  []string
}

// Provider is a fake OIDC provider. Use Issuer and ClientID in the application's
// identity configuration; any client secret is accepted. It also issues client
// credentials tokens to any confidential client for any resource, so a service
// call can be tested end to end; whether a client may request a resource is
// Rauthy's decision, not the application's.
type Provider struct {
	Issuer   string
	ClientID string
	key      *rsa.PrivateKey
	mu       sync.Mutex
	codes    map[string]pendingLogin
}

type pendingLogin struct {
	user             User
	nonce, challenge string
	sid              string
}

// NewProvider starts a fake provider that stops when the test ends.
func NewProvider(t testing.TB) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{ClientID: "appkit-test", key: key, codes: make(map[string]pendingLogin)}
	server := httptest.NewServer(http.HandlerFunc(provider.serve))
	t.Cleanup(server.Close)
	provider.Issuer = server.URL
	return provider
}

func (provider *Provider) serve(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"issuer": provider.Issuer, "authorization_endpoint": provider.Issuer + "/authorize", "token_endpoint": provider.Issuer + "/token",
			"jwks_uri": provider.Issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}, "backchannel_logout_supported": true,
		})
	case "/keys":
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &provider.key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
	case "/token":
		_ = request.ParseForm()
		if request.Form.Get("grant_type") == "client_credentials" {
			if request.Form.Get("client_id") == "" || request.Form.Get("client_secret") == "" {
				http.Error(writer, `{"error":"invalid_client"}`, http.StatusUnauthorized)
				return
			}
			access, err := provider.token("at+jwt", provider.clientClaims(request.Form.Get("client_id"), request.Form["resource"]...))
			if err != nil {
				http.Error(writer, `{"error":"server_error"}`, http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 1800})
			return
		}
		provider.mu.Lock()
		login, ok := provider.codes[request.Form.Get("code")]
		delete(provider.codes, request.Form.Get("code"))
		provider.mu.Unlock()
		verifier := sha256.Sum256([]byte(request.Form.Get("code_verifier")))
		if !ok || request.Form.Get("client_id") != provider.ClientID || base64.RawURLEncoding.EncodeToString(verifier[:]) != login.challenge {
			http.Error(writer, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		access, err := provider.token("at+jwt", provider.claims(login.user))
		if err != nil {
			http.Error(writer, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		hash := sha256.Sum256([]byte(access))
		claims := provider.claims(login.user)
		claims["nonce"], claims["sid"], claims["at_hash"] = login.nonce, login.sid, base64.RawURLEncoding.EncodeToString(hash[:16])
		id, err := provider.token("JWT", claims)
		if err != nil {
			http.Error(writer, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{"access_token": access, "id_token": id, "token_type": "Bearer", "expires_in": 3600})
	default:
		http.NotFound(writer, request)
	}
}

func (provider *Provider) claims(user User) map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": provider.Issuer, "aud": provider.ClientID, "sub": user.Subject, "email": user.Email, "groups": user.Groups, "iat": now, "exp": now + 3600}
}

// clientClaims are a client credentials token as Rauthy issues it: no subject,
// the client in azp, and the audience the client plus each granted resource.
func (provider *Provider) clientClaims(clientID string, resources ...string) map[string]any {
	now := time.Now().Unix()
	audience := []string{clientID}
	for _, resource := range resources {
		if resource != "" && resource != clientID {
			audience = append(audience, resource)
		}
	}
	return map[string]any{"iss": provider.Issuer, "aud": audience, "azp": clientID, "iat": now, "exp": now + 1800}
}

func (provider *Provider) token(tokenType string, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: provider.key}, (&jose.SignerOptions{}).WithType(jose.ContentType(tokenType)).WithHeader("kid", "test"))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

// AccessToken returns a bearer access token for user, accepted by bearer routes.
func (provider *Provider) AccessToken(t testing.TB, user User) string {
	t.Helper()
	token, err := provider.token("at+jwt", provider.claims(user))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// ClientToken returns the access token Rauthy would issue to the application
// whose Rauthy client ID is clientID when it requests resources, so bearer
// routes can be tested as another application calls them. Include the tested
// application's ClientID in resources, or its routes refuse the token.
func (provider *Provider) ClientToken(t testing.TB, clientID string, resources ...string) string {
	t.Helper()
	token, err := provider.token("at+jwt", provider.clientClaims(clientID, resources...))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// SignIn runs the real browser sign-in flow against the application at appURL,
// which must match its configured origin, and returns the session cookie.
func (provider *Provider) SignIn(t testing.TB, appURL string, user User) *http.Cookie {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(strings.TrimSuffix(appURL, "/") + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != http.StatusSeeOther || !strings.HasPrefix(location.String(), provider.Issuer+"/authorize") {
		t.Fatalf("identitytest: /auth/login did not redirect to the fake provider (status %d)", response.StatusCode)
	}
	query := location.Query()
	code := rand.Text()
	provider.mu.Lock()
	provider.codes[code] = pendingLogin{user: user, nonce: query.Get("nonce"), challenge: query.Get("code_challenge"), sid: rand.Text()}
	provider.mu.Unlock()
	callback, err := http.NewRequest(http.MethodGet, query.Get("redirect_uri")+"?"+url.Values{"state": {query.Get("state")}, "code": {code}}.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range response.Cookies() {
		callback.AddCookie(cookie)
	}
	response, err = client.Do(callback)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	for _, cookie := range response.Cookies() {
		if cookie.Value != "" && !strings.HasSuffix(cookie.Name, "_login") {
			return cookie
		}
	}
	t.Fatalf("identitytest: sign-in failed (callback status %d)", response.StatusCode)
	return nil
}

// CreateKey makes a key for the signed-in person through /auth/keys, as the
// Account page does, and returns its id, for revoking it, and its secret. It
// asks for the application's maximum lifetime, read from /auth/session, and
// fails the test when the application lists nothing delegable or refuses the
// key.
func (provider *Provider) CreateKey(t testing.TB, appURL string, cookie *http.Cookie, name string, scopes ...string) (id, secret string) {
	t.Helper()
	base := strings.TrimSuffix(appURL, "/")
	request, err := http.NewRequest(http.MethodGet, base+"/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
	var session struct {
		Keys *struct {
			MaxLifetimeSeconds int64 `json:"max_lifetime_seconds"`
		} `json:"keys"`
	}
	provider.call(t, request, http.StatusOK, &session)
	if session.Keys == nil {
		t.Fatal("identitytest: the application lists nothing delegable, so this person can make no key")
	}
	body, _ := json.Marshal(map[string]any{"name": name, "scopes": scopes, "lifetime_seconds": session.Keys.MaxLifetimeSeconds})
	request, err = http.NewRequest(http.MethodPost, base+"/auth/keys", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(cookie)
	request.Header.Set("Origin", base)
	request.Header.Set("Content-Type", "application/json")
	var made struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
		Secret string `json:"secret"`
	}
	provider.call(t, request, http.StatusCreated, &made)
	return made.Key.ID, made.Secret
}

func (provider *Provider) call(t testing.TB, request *http.Request, want int, answer any) {
	t.Helper()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("identitytest: %s %s answered %d: %s", request.Method, request.URL.Path, response.StatusCode, data)
	}
	if err := json.Unmarshal(data, answer); err != nil {
		t.Fatalf("identitytest: %s %s answered no JSON: %s", request.Method, request.URL.Path, data)
	}
}
