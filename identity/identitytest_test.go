package identity_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
)

// TestIdentityTestHelper is how an application tests its routes without Rauthy.
func TestIdentityTestHelper(t *testing.T) {
	provider := identitytest.NewProvider(t)
	app := httptest.NewServer(nil)
	defer app.Close()
	policy, _ := authz.New(map[string][]string{"observer": {"diagnostics.read"}}, map[string][]string{"observers": {"observer"}}, map[string][]string{"monitor": {"observer"}}, nil)
	sessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL,
		DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	router := sessions.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit, ClientAddress: mustClientAddress(t, "remote")})
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, _ := identity.FromContext(r.Context())
		_, _ = w.Write([]byte(actor.Subject))
	})
	router.Private("GET /page", "diagnostics.read", ok)
	router.Service("GET /api", "diagnostics.read", ok)
	app.Config.Handler = router

	alice := identitytest.User{Subject: "alice", Email: "alice@example.test", Groups: []string{"observers"}}
	cookie := provider.SignIn(t, app.URL, alice)
	get := func(path string, edit func(*http.Request)) (int, string) {
		request, _ := http.NewRequest(http.MethodGet, app.URL+path, nil)
		edit(request)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	withCookie := func(r *http.Request) { r.AddCookie(cookie) }
	if status, body := get("/page", withCookie); status != 200 || body != "alice" {
		t.Fatalf("signed-in page: %d %q", status, body)
	}
	if status, body := get("/auth/session", withCookie); status != 200 || !strings.Contains(body, "diagnostics.read") {
		t.Fatalf("session permissions: %d %q", status, body)
	}
	token := provider.AccessToken(t, alice)
	if status, body := get("/api", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }); status != 200 || body != "alice" {
		t.Fatalf("bearer route: %d %q", status, body)
	}
	if status, _ := get("/api", withCookie); status != 401 {
		t.Fatalf("bearer route accepted a cookie: %d", status)
	}
	// Another application calls the bearer route with a client token.
	for name, test := range map[string]struct {
		token  string
		status int
		body   string
	}{
		"listed client":   {provider.ClientToken(t, "monitor", provider.ClientID), 200, "monitor"},
		"unlisted client": {provider.ClientToken(t, "stranger", provider.ClientID), 403, `"error"`},
		"other audience":  {provider.ClientToken(t, "monitor", "billing"), 401, `"error"`},
	} {
		if status, body := get("/api", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+test.token) }); status != test.status || !strings.Contains(body, test.body) {
			t.Fatalf("%s: %d %q", name, status, body)
		}
	}
}

// TestServiceClient is how an application calls another one: its sessions
// obtain client tokens addressed to the other application's client ID.
func TestServiceClient(t *testing.T) {
	provider := identitytest.NewProvider(t)
	accounts := httptest.NewServer(nil)
	defer accounts.Close()
	policy, _ := authz.New(map[string][]string{"reader": {"profiles.read"}}, nil, map[string][]string{"notes": {"reader"}}, nil)
	accountsSessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: accounts.URL,
		DatabasePath: filepath.Join(t.TempDir(), "accounts-sessions.sqlite"), Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer accountsSessions.Close()
	router := accountsSessions.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit, ClientAddress: mustClientAddress(t, "remote")})
	router.Service("GET /api/profiles", "profiles.read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, _ := identity.FromContext(r.Context())
		_, _ = w.Write([]byte(caller.Subject))
	}))
	accounts.Config.Handler = router

	notesPolicy, _ := authz.New(nil, nil, nil, nil)
	notesSessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: "notes", ClientSecret: "notes-secret", Origin: "http://localhost:8081",
		DatabasePath: filepath.Join(t.TempDir(), "notes-sessions.sqlite"), Policy: notesPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer notesSessions.Close()
	if _, err := notesSessions.ServiceClient(""); err == nil {
		t.Fatal("empty target accepted")
	}
	client, err := notesSessions.ServiceClient(provider.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(accounts.URL + "/api/profiles")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || string(body) != "notes" {
		t.Fatalf("service call: %d %q", response.StatusCode, body)
	}
	public, _ := authz.New(nil, nil, nil, nil)
	publicSessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: "public", Origin: "http://localhost:8082",
		DatabasePath: filepath.Join(t.TempDir(), "public-sessions.sqlite"), Policy: public,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer publicSessions.Close()
	if _, err := publicSessions.ServiceClient(provider.ClientID); err == nil {
		t.Fatal("public client made a service client")
	}
}

// TestSessionSchemaVersion checks a database from a newer AppKit is refused, not misread.
func TestSessionSchemaVersion(t *testing.T) {
	provider := identitytest.NewProvider(t)
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	policy, _ := authz.New(nil, nil, nil, nil)
	config := identity.SessionConfig{Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: "http://localhost:8080", DatabasePath: path, Policy: policy}
	sessions, err := identity.NewSessions(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	sessions.Close()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := identity.NewSessions(context.Background(), config); err == nil || !strings.Contains(err.Error(), "newer") {
		if s != nil {
			s.Close()
		}
		t.Fatalf("newer schema accepted: %v", err)
	}
}
