package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Ovi1kanobe/appkit/config"
	"github.com/Ovi1kanobe/appkit/frontend"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
	"github.com/Ovi1kanobe/appkit/schema"

	"github.com/Ovi1kanobe/appkit/examples/starter/systems/userprofiles"
)

// TestRoutes signs users in against a local fake Rauthy and exercises the
// real routes.
func TestRoutes(t *testing.T) {
	ctx := context.Background()
	provider := identitytest.NewProvider(t)
	app := httptest.NewServer(nil)
	defer app.Close()
	policy, err := newPolicy()
	if err != nil {
		t.Fatal(err)
	}
	database, err := schema.Open(ctx, filepath.Join(t.TempDir(), "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profiles, err := userprofiles.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := identity.NewSessions(ctx, identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL,
		DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy, OnSessionRequest: recordProfile(profiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	pages, err := frontend.New(fstest.MapFS{"index.html": {Data: []byte("app")}}, frontend.Config{HashedAssets: "assets"})
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = routes(sessions, remoteClientAddress(t), pages)

	memberCookie := provider.SignIn(t, app.URL, identitytest.User{Subject: "sam", Email: "sam@example.test", Groups: []string{membersGroup}})
	send := func(cookie *http.Cookie, method, path, body string) (int, string) {
		t.Helper()
		request, err := http.NewRequest(method, app.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", app.URL)
		request.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	for _, step := range []struct {
		name         string
		cookie       *http.Cookie
		method, path string
		body         string
		status       int
		contains     string
	}{
		{"health without sign-in", nil, "GET", "/api/health", "", 200, `{"status":"ok"}`},
		{"signed out session", nil, "GET", "/auth/session", "", 200, `"user":null`},
		{"member signed in", memberCookie, "GET", "/auth/session", "", 200, `"sam"`},
		{"page", nil, "GET", "/", "", 200, "app"},
		{"no keys while nothing is delegable", memberCookie, "POST", "/auth/keys", `{"name":"ci","scopes":["x"],"lifetime_seconds":60}`, 400, "does not issue keys"},
	} {
		status, body := send(step.cookie, step.method, step.path, step.body)
		if status != step.status || !strings.Contains(body, step.contains) {
			t.Fatalf("%s: %d %q, want %d containing %q", step.name, status, body, step.status, step.contains)
		}
		if step.path == "/auth/session" && strings.Contains(body, `"keys"`) {
			t.Fatalf("%s: keys offered while nothing is delegable: %s", step.name, body)
		}
	}
	// Health answers a probe that reaches the app by address, and a page is the
	// shell, revalidated against its ETag.
	probe, _ := http.NewRequest("GET", app.URL+"/api/health", nil)
	probe.Host = "10.0.0.5:8080"
	page, _ := http.NewRequest("GET", app.URL+"/account", nil)
	for _, request := range []*http.Request{probe, page} {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("%s: %d", request.URL.Path, response.StatusCode)
		}
		if request == page && (response.Header.Get("Cache-Control") != "no-cache" || response.Header.Get("ETag") == "") {
			t.Fatalf("page cache-control %q etag %q", response.Header.Get("Cache-Control"), response.Header.Get("ETag"))
		}
	}
	// The session request recorded the member's profile.
	recorded, err := profiles.Lookup(ctx, []string{"sam"})
	if err != nil || recorded["sam"].Email != "sam@example.test" {
		t.Fatalf("profile after session request: %+v %v", recorded, err)
	}
}

// remoteClientAddress is the CLIENT_ADDRESS rule tests and the preview use:
// the connection's own address, since no proxy sits in front of them.
func remoteClientAddress(t testing.TB) func(*http.Request) string {
	t.Helper()
	clientAddress, err := config.ParseClientAddress("remote")
	if err != nil {
		t.Fatal(err)
	}
	return clientAddress
}
