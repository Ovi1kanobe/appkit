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

	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
)

// TestIdentityTestHelper is how an application tests its routes without Rauthy.
func TestIdentityTestHelper(t *testing.T) {
	provider := identitytest.NewProvider(t)
	app := httptest.NewServer(http.NewServeMux())
	defer app.Close()
	policy, _ := authz.New(map[string][]string{"observer": {"diagnostics.read"}}, map[string][]string{"observers": {"observer"}})
	sessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL,
		DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	mux := http.NewServeMux()
	sessions.Routes(mux)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, _ := identity.FromContext(r.Context())
		_, _ = w.Write([]byte(actor.Subject))
	})
	mux.Handle("/page", sessions.Require(ok))
	mux.Handle("/api", sessions.Bearer(ok))
	app.Config.Handler = mux

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
}

// TestRequirePermission checks the 401/403/200 outcomes of identity.RequirePermission.
func TestRequirePermission(t *testing.T) {
	handler := identity.RequirePermission("diagnostics.read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, test := range []struct {
		actor  *identity.Identity
		status int
	}{{nil, 401}, {&identity.Identity{Subject: "a"}, 403}, {&identity.Identity{Subject: "a", Permissions: []string{"diagnostics.read"}}, 200}} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		if test.actor != nil {
			request = request.WithContext(identity.WithContext(request.Context(), *test.actor))
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("status %d, want %d", response.Code, test.status)
		}
	}
}

// TestSessionSchemaVersion checks a database from a newer AppKit is refused, not misread.
func TestSessionSchemaVersion(t *testing.T) {
	provider := identitytest.NewProvider(t)
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	policy, _ := authz.New(nil, nil)
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
