package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Ovi1kanobe/appkit/config"
	"github.com/Ovi1kanobe/appkit/encryption"
	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	httpapi "github.com/Ovi1kanobe/appkit/examples/minimal/api/http"
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
	hub := &realtime.Hub{}
	defer hub.Close()
	app.Config.Handler = routes(sessions, remoteClientAddress(t), profiles, diagnostics.New(), noteSystem, emailSystem, hub, pages)

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
	// Health answers a probe that reaches the app by address, and a page is the
	// shell, revalidated against its ETag.
	probe, _ := http.NewRequest("GET", app.URL+"/api/health", nil)
	probe.Host = "10.0.0.5:8080"
	page, _ := http.NewRequest("GET", app.URL+"/dashboard", nil)
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
	// The public notes route answers anyone, signed out, with exactly the
	// fields its public read rule lists.
	if status, _ := send(aliceCookie, "POST", "/api/notes", `{"text":"for everyone"}`); status != 201 {
		t.Fatalf("seed a public note: %d", status)
	}
	status, body := send(nil, "GET", httpapi.PublicNotesPattern[len("GET "):], "")
	var publicNotes []map[string]any
	if err := json.Unmarshal([]byte(body), &publicNotes); status != 200 || err != nil || len(publicNotes) == 0 {
		t.Fatalf("public notes: %d %q %v", status, body, err)
	}
	for _, note := range publicNotes {
		keys := slices.Sorted(maps.Keys(note))
		if strings.Join(keys, ",") != "created_at,id,text" {
			t.Fatalf("public note keys %v, want created_at, id, text", keys)
		}
	}
	// A visitor on any origin posts a note signed out: it is the public
	// subject's, answered with exactly the public fields, shown to members as
	// no one's, and deleted by no member. Preflights are free, and the sixth
	// post in a minute from one address is refused.
	publicNotesPath := httpapi.CreatePublicNotePattern[len("POST "):]
	visitor := func(method, contentType, body string) (int, http.Header, string) {
		t.Helper()
		request, err := http.NewRequest(method, app.URL+publicNotesPath, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "https://visitor.example")
		if method == http.MethodOptions {
			request.Header.Set("Access-Control-Request-Method", "POST")
			request.Header.Set("Access-Control-Request-Headers", "content-type")
		}
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, response.Header, string(data)
	}
	status, header, body := visitor("POST", "application/json", `{"text":"from a visitor"}`)
	var visitorNote map[string]any
	if err := json.Unmarshal([]byte(body), &visitorNote); status != 201 || err != nil || header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("visitor note: %d %q %v %v", status, body, err, header)
	}
	if keys := slices.Sorted(maps.Keys(visitorNote)); strings.Join(keys, ",") != "created_at,id,text" {
		t.Fatalf("visitor note keys %v, want created_at, id, text", keys)
	}
	visitorNoteID := int64(visitorNote["id"].(float64))
	if note, err := noteSystem.Get(ctx, visitorNoteID); err != nil || note.CreatedBy != identity.PublicSubject {
		t.Fatalf("visitor note author: %+v %v", note, err)
	}
	// The app knows no email for the public subject, so the field is left out, not sent empty.
	_, body = send(aliceCookie, "GET", "/api/notes", "")
	var memberNotes []map[string]any
	if err := json.Unmarshal([]byte(body), &memberNotes); err != nil {
		t.Fatalf("notes as alice: %q %v", body, err)
	}
	seen := slices.IndexFunc(memberNotes, func(note map[string]any) bool { return note["id"] == float64(visitorNoteID) })
	if seen < 0 {
		t.Fatalf("visitor note missing for alice: %s", body)
	}
	if _, hasAuthorEmail := memberNotes[seen]["author_email"]; hasAuthorEmail || memberNotes[seen]["mine"] != false {
		t.Fatalf("visitor note as alice: %s", body)
	}
	if status, _ := send(aliceCookie, "DELETE", fmt.Sprintf("/api/notes/%d", visitorNoteID), ""); status != 403 {
		t.Fatalf("alice deleted the visitor note: %d", status)
	}
	if status, _, body := visitor("POST", "", `{"text":"no content type"}`); status != 415 || body != `{"error":"Send JSON with Content-Type: application/json."}`+"\n" {
		t.Fatalf("visitor note without the JSON content type: %d %q", status, body)
	}
	if status, header, _ := visitor("OPTIONS", "", ""); status != 204 || header.Get("Access-Control-Allow-Methods") != "GET, HEAD, POST" || header.Get("Access-Control-Allow-Headers") != "Content-Type" {
		t.Fatalf("visitor preflight: %d %v", status, header)
	}
	// From three: the 415 above spent a token, since the limiter runs before the content type check.
	for count := 3; count <= 5; count++ {
		if status, _, body := visitor("POST", "application/json", `{"text":"again"}`); status != 201 {
			t.Fatalf("visitor note %d: %d %q", count, status, body)
		}
	}
	if status, header, _ := visitor("POST", "application/json", `{"text":"one too many"}`); status != 429 || header.Get("Retry-After") == "" {
		t.Fatalf("sixth visitor note in a minute: %d %v", status, header)
	}
	// A key a member made reaches the routes its scope covers as that member,
	// is refused where its scope does not reach, and ends when revoked.
	keyID, secret := provider.CreateKey(t, app.URL, aliceCookie, "ci", access.NotesRead)
	withKey := func(method, path string) int {
		t.Helper()
		request, _ := http.NewRequest(method, app.URL+path, strings.NewReader(`{"text":"by key"}`))
		request.Header.Set("Authorization", "Bearer "+secret)
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if status := withKey("GET", "/api/notes"); status != 200 {
		t.Fatalf("key with its scope: %d", status)
	}
	if status := withKey("POST", "/api/notes"); status != 403 {
		t.Fatalf("key without the scope: %d", status)
	}
	if status, _ := send(aliceCookie, "DELETE", "/auth/keys/"+keyID, ""); status != 204 {
		t.Fatalf("revoke: %d", status)
	}
	if status := withKey("GET", "/api/notes"); status != 401 {
		t.Fatalf("revoked key: %d", status)
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

// remoteClientAddress is the CLIENT_ADDRESS rule tests and the preview use:
// the connection's own address, since no proxy sits in front of them.
func remoteClientAddress(t testing.TB) func(*http.Request) string {
	t.Helper()
	clientAddress, err := config.ParseClientAddress("remote", "")
	if err != nil {
		t.Fatal(err)
	}
	return clientAddress
}
