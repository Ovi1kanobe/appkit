package identity_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
	"github.com/coder/websocket"
)

// keyFixture is the session fixture with a policy that delegates one of the
// two permissions the observer role grants, and an admin permission for keys.
func keyFixture(t *testing.T) *sessionFixture {
	t.Helper()
	f := newSessionFixture(t, 0, "")
	f.sessions.Close()
	f.config.Policy, _ = authz.New(map[string][]string{"observer": {"diagnostics.read", "notes.write"}}, map[string][]string{"observers": {"observer"}}, nil, []string{"diagnostics.read"})
	f.config.KeyAdminPermission = "notes.write"
	f.open()
	return f
}

type keyAnswer struct {
	Key struct {
		ID          string
		Permissions []string
		RevokedAt   *time.Time `json:"revoked_at"`
	}
	Keys   []json.RawMessage
	Secret string
}

func (f *sessionFixture) createKey(cookie *http.Cookie, body string, want int) keyAnswer {
	f.t.Helper()
	var answer keyAnswer
	json.Unmarshal([]byte(status(f.t, f.request("POST", "/auth/keys", cookie, map[string]string{"Origin": f.app.URL, "Content-Type": "application/json"}, body), want)), &answer)
	return answer
}

func (f *sessionFixture) keySocket(secret string) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return websocket.Dial(ctx, strings.Replace(f.app.URL, "http:", "ws:", 1)+"/socket", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + secret}}})
}

func TestKeys(t *testing.T) {
	f := keyFixture(t)
	alice, _ := f.login("alice")
	bearer := func(secret string) map[string]string { return map[string]string{"Authorization": "Bearer " + secret} }
	valid := `{"name":"ci","scopes":["diagnostics.read"],"lifetime_seconds":3600}`

	// A browser learns what it may give a key.
	if body := status(t, f.request("GET", "/auth/session", alice, nil, ""), 200); !strings.Contains(body, `"keys":{"delegable":["diagnostics.read"],"max_lifetime_seconds":2592000}`) {
		t.Fatalf("session keys: %s", body)
	}
	// Creation needs the browser's origin, and checks the name, scopes, and lifetime.
	status(t, f.request("POST", "/auth/keys", alice, map[string]string{"Content-Type": "application/json"}, valid), 403)
	for _, body := range []string{
		`{"name":"ci","scopes":["notes.write"],"lifetime_seconds":3600}`,
		`{"name":"ci","scopes":["bots.read"],"lifetime_seconds":3600}`,
		`{"name":"ci","scopes":[],"lifetime_seconds":3600}`,
		`{"name":"ci","scopes":["diagnostics.read"]}`,
		`{"name":"ci","scopes":["diagnostics.read"],"lifetime_seconds":9999999}`,
		`{"name":"ci","scopes":["diagnostics.read"],"lifetime_seconds":18446744075}`,
		`{"name":"   ","scopes":["diagnostics.read"],"lifetime_seconds":3600}`,
		`{"name":"","scopes":["diagnostics.read"],"lifetime_seconds":3600}`,
		`{"name":"` + strings.Repeat("n", 65) + `","scopes":["diagnostics.read"],"lifetime_seconds":3600}`,
		`not json`,
	} {
		f.createKey(alice, body, 400)
	}
	f.createKey(alice, `{"name":"ci","scopes":["diagnostics.read"],"lifetime_seconds":3600,"pad":"`+strings.Repeat("p", 5000)+`"}`, 413)
	made := f.createKey(alice, valid, 201)
	if !strings.HasPrefix(made.Secret, "ak_") || len(made.Secret) != 46 || made.Key.ID == "" || strings.Join(made.Key.Permissions, ",") != "diagnostics.read" {
		t.Fatalf("created key %+v", made)
	}

	// The key calls routes as alice, with only its permissions, and tells /auth/session about itself.
	var who struct {
		Subject     string
		Permissions []string
	}
	json.Unmarshal([]byte(status(t, f.request("GET", "/protected", nil, bearer(made.Secret), ""), 200)), &who)
	if who.Subject != "alice" || strings.Join(who.Permissions, ",") != "diagnostics.read" {
		t.Fatalf("key identity %+v", who)
	}
	f.sessions.Close()
	f.config.OnSessionRequest = func(*http.Request, identity.Identity) (any, error) {
		t.Fatal("app info ran for a key")
		return nil, nil
	}
	f.open()
	if body := status(t, f.request("GET", "/auth/session", nil, bearer(made.Secret), ""), 200); !strings.Contains(body, `"key_id":"`+made.Key.ID+`"`) || !strings.Contains(body, `"key":{"expires_at":`) || !strings.Contains(body, `"scopes":["diagnostics.read"]`) {
		t.Fatalf("key session: %s", body)
	}
	status(t, f.request("GET", "/diagnostics", nil, bearer(made.Secret), ""), 200)
	status(t, f.request("GET", "/notes", nil, bearer(made.Secret), ""), 403)
	status(t, f.request("POST", "/mutate", nil, bearer(made.Secret), ""), 200) // No CSRF check for a key.

	// A Bearer header is never anonymous and never falls back to the cookie; other schemes are ignored.
	response := f.request("GET", "/protected", alice, bearer("ak_"+strings.Repeat("x", 43)), "")
	if status(t, response, 401); response.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("missing challenge")
	}
	status(t, f.request("GET", "/protected", alice, bearer("fixture"), ""), 401)
	status(t, f.request("GET", "/auth/session", nil, bearer("fixture"), ""), 401)
	status(t, f.request("GET", "/protected", alice, map[string]string{"Authorization": "Basic Zm9vOmJhcg=="}, ""), 200)
	status(t, f.request("GET", "/bearer", nil, bearer(made.Secret), ""), 401)
	// A key manages no keys.
	status(t, f.request("GET", "/auth/keys", nil, bearer(made.Secret), ""), 403)
	status(t, f.request("POST", "/auth/keys", nil, bearer(made.Secret), valid), 403)
	status(t, f.request("GET", "/auth/users/alice/keys", nil, bearer(made.Secret), ""), 403)

	// Someone else's revoke is a silent 204; the holder's ends the key, its socket, and is idempotent.
	bob := f.begin("bob", func(c map[string]any) { c["sub"] = "bob" })
	bobCookie := f.finish(bob).Cookies()[1]
	status(t, f.request("DELETE", "/auth/keys/"+made.Key.ID, bobCookie, map[string]string{"Origin": f.app.URL}, ""), 204)
	status(t, f.request("GET", "/diagnostics", nil, bearer(made.Secret), ""), 200)
	socket, _, err := f.keySocket(made.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	status(t, f.request("DELETE", "/auth/keys/"+made.Key.ID, alice, map[string]string{"Origin": f.app.URL}, ""), 204)
	mustClose(t, socket)
	status(t, f.request("GET", "/diagnostics", nil, bearer(made.Secret), ""), 401)
	status(t, f.request("DELETE", "/auth/keys/"+made.Key.ID, alice, map[string]string{"Origin": f.app.URL}, ""), 204)
	var listed keyAnswer
	json.Unmarshal([]byte(status(t, f.request("GET", "/auth/keys", alice, nil, ""), 200)), &listed)
	if len(listed.Keys) != 1 || !strings.Contains(string(listed.Keys[0]), `"revoked_at":"`) || strings.Contains(string(listed.Keys[0]), made.Secret[3:]) {
		t.Fatalf("listed keys: %s", listed.Keys)
	}

	// A sign-in refreshes the holder's keys: losing the group narrows them to nothing and ends their sockets; regaining it restores them.
	second := f.createKey(alice, valid, 201)
	socket, _, err = f.keySocket(second.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	if response := f.finish(f.begin("alice-stranger", func(c map[string]any) { c["groups"] = []string{"strangers"} })); response.StatusCode != 403 {
		t.Fatalf("stranger sign-in %d", response.StatusCode)
	}
	mustClose(t, socket)
	status(t, f.request("GET", "/diagnostics", nil, bearer(second.Secret), ""), 401)
	f.login("alice-again")
	status(t, f.request("GET", "/diagnostics", nil, bearer(second.Secret), ""), 200)

	// An admin lists and revokes another person's keys from a browser.
	status(t, f.request("GET", "/auth/users/alice/keys", alice, nil, ""), 200)
	bobKeys := status(t, f.request("GET", "/auth/users/alice/keys", bobCookie, nil, ""), 200)
	if !strings.Contains(bobKeys, second.Key.ID) {
		t.Fatalf("admin list: %s", bobKeys)
	}
	status(t, f.request("DELETE", "/auth/users/alice/keys", bobCookie, map[string]string{"Origin": f.app.URL}, ""), 204)
	status(t, f.request("GET", "/diagnostics", nil, bearer(second.Secret), ""), 401)

	// Keys persist across restarts as hashes, expire on their own, and are capped.
	third := f.createKey(alice, valid, 201)
	f.sessions.Close()
	stored, err := os.ReadFile(f.config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), third.Secret[3:]) {
		t.Fatal("key secret persisted")
	}
	f.open()
	status(t, f.request("GET", "/diagnostics", nil, bearer(third.Secret), ""), 200)
	short := f.createKey(alice, `{"name":"short","scopes":["diagnostics.read"],"lifetime_seconds":1}`, 201)
	status(t, f.request("GET", "/diagnostics", nil, bearer(short.Secret), ""), 200)
	time.Sleep(1100 * time.Millisecond)
	status(t, f.request("GET", "/diagnostics", nil, bearer(short.Secret), ""), 401)
	// Dead keys are listed, but never more than the cap of them.
	for i := 0; i < 25; i++ {
		made := f.createKey(alice, `{"name":"gone","scopes":["diagnostics.read"],"lifetime_seconds":3600}`, 201)
		status(t, f.request("DELETE", "/auth/keys/"+made.Key.ID, alice, map[string]string{"Origin": f.app.URL}, ""), 204)
	}
	// One live key, the 20 dead ones kept at the last creation, and the one revoked after it.
	json.Unmarshal([]byte(status(t, f.request("GET", "/auth/keys", alice, nil, ""), 200)), &listed)
	if len(listed.Keys) > 22 {
		t.Fatalf("%d keys listed", len(listed.Keys))
	}
	for i := 0; i < 19; i++ {
		f.createKey(alice, fmt.Sprintf(`{"name":"key %d","scopes":["diagnostics.read"],"lifetime_seconds":3600}`, i), 201)
	}
	f.createKey(alice, valid, 409)

}

// TestKeysNotIssued checks an app that lists nothing delegable: no keys object
// for browsers, and no key can be made.
func TestKeysNotIssued(t *testing.T) {
	f := newSessionFixture(t, 0, "")
	cookie, _ := f.login("none")
	if body := status(t, f.request("GET", "/auth/session", cookie, nil, ""), 200); strings.Contains(body, "keys") {
		t.Fatalf("keys offered: %s", body)
	}
	f.createKey(cookie, `{"name":"ci","scopes":["diagnostics.read"],"lifetime_seconds":60}`, 400)
	status(t, f.request("GET", "/auth/users/alice/keys", cookie, nil, ""), 404)
}

// TestIdentityTestKey is how an application tests a route a key may call.
func TestIdentityTestKey(t *testing.T) {
	provider := identitytest.NewProvider(t)
	app := httptest.NewServer(nil)
	defer app.Close()
	policy, _ := authz.New(map[string][]string{"observer": {"diagnostics.read"}}, map[string][]string{"observers": {"observer"}}, nil, []string{"diagnostics.read"})
	sessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL, DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	router := sessions.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit})
	router.Private("GET /api/diagnostics", "diagnostics.read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	app.Config.Handler = router
	cookie := provider.SignIn(t, app.URL, identitytest.User{Subject: "alice", Groups: []string{"observers"}})
	id, secret := provider.CreateKey(t, app.URL, cookie, "ci", "diagnostics.read")
	call := func() int {
		request, _ := http.NewRequest("GET", app.URL+"/api/diagnostics", nil)
		request.Header.Set("Authorization", "Bearer "+secret)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if call() != 200 {
		t.Fatal("key refused")
	}
	request, _ := http.NewRequest("DELETE", app.URL+"/auth/keys/"+id, nil)
	request.AddCookie(cookie)
	request.Header.Set("Origin", app.URL)
	if response, err := http.DefaultClient.Do(request); err != nil || response.StatusCode != 204 {
		t.Fatalf("revoke %v %v", err, response)
	}
	if call() != 401 {
		t.Fatal("revoked key accepted")
	}
}
