package main

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Ovi1kanobe/appkit/encryption"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/userprofiles"
	"github.com/Ovi1kanobe/appkit/frontend"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
	"github.com/Ovi1kanobe/appkit/realtime"
	"github.com/Ovi1kanobe/appkit/schema"
)

// TestRoutes signs users in against a local fake Rauthy and exercises the
// real routes, permissions, and ownership rules.
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
	noteSystem, err := notes.Open(ctx, database, func(notes.Change) {})
	if err != nil {
		t.Fatal(err)
	}
	masterKey, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	emailSystem, err := email.Open(ctx, database, masterKey, func(email.Change) {})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := identity.NewSessions(ctx, identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL,
		DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy, AppInfo: recordProfile(profiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	pages, err := frontend.New(fstest.MapFS{"index.html": {Data: []byte("app")}})
	if err != nil {
		t.Fatal(err)
	}
	hub := &realtime.Hub{}
	defer hub.Close()
	app.Config.Handler = routes(sessions, profiles, diagnostics.New(), noteSystem, emailSystem, hub, pages)

	alice := identitytest.User{Subject: "alice", Email: "alice@example.test", Groups: []string{memberGroup}}
	aliceCookie := provider.SignIn(t, app.URL, alice)
	bobCookie := provider.SignIn(t, app.URL, identitytest.User{Subject: "bob", Email: "bob@example.test", Groups: []string{memberGroup}})
	adminCookie := provider.SignIn(t, app.URL, identitytest.User{Subject: "ada", Email: "ada@example.test", Groups: []string{adminGroup}})
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
		{"signed out", nil, "GET", "/api/notes", "", 401, `{"error":"Sign in required."}`},
		{"no permission", adminCookie, "GET", "/api/notes", "", 403, `"error"`},
		{"session records the profile", aliceCookie, "GET", "/auth/session", "", 200, `"alice@example.test"`},
		{"create", aliceCookie, "POST", "/api/notes", `{"text":"hello"}`, 201, `"author_email":"alice@example.test"`},
		{"invalid", aliceCookie, "POST", "/api/notes", `{"text":" "}`, 400, `"error"`},
		{"other reader", bobCookie, "GET", "/api/notes", "", 200, `"mine":false`},
		{"not owner", bobCookie, "DELETE", "/api/notes/1", "", 403, `"error"`},
		{"owner deletes", aliceCookie, "DELETE", "/api/notes/1", "", 204, ""},
		{"already gone", aliceCookie, "DELETE", "/api/notes/1", "", 404, `"error"`},
		{"member cannot set key", aliceCookie, "PUT", "/api/email/key", `{"api_key":"re_live_1234abcd"}`, 403, `"error"`},
		{"admin sets key", adminCookie, "PUT", "/api/email/key", `{"api_key":"re_live_1234abcd"}`, 204, ""},
		{"key never returned", adminCookie, "GET", "/api/email/key", "", 200, `"last_four":"abcd"`},
	} {
		status, body := send(step.cookie, step.method, step.path, step.body)
		if status != step.status || !strings.Contains(body, step.contains) {
			t.Fatalf("%s: %d %q, want %d containing %q", step.name, status, body, step.status, step.contains)
		}
	}
	// Bearer routes serve a person's access token and, through a client
	// credentials token addressed to this application, a calling application.
	for _, step := range []struct {
		name   string
		token  string
		status int
	}{
		{"person", provider.AccessToken(t, alice), 200},
		{"listed client", provider.ClientToken(t, monitorClient, provider.ClientID), 200},
		{"unlisted client", provider.ClientToken(t, "stranger", provider.ClientID), 403},
		{"client token for another application", provider.ClientToken(t, monitorClient, "billing"), 401},
	} {
		request, _ := http.NewRequest("GET", app.URL+"/api/status", nil)
		request.Header.Set("Authorization", "Bearer "+step.token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != step.status {
			t.Fatalf("bearer %s: %d, want %d", step.name, response.StatusCode, step.status)
		}
	}
}
