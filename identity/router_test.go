package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
)

// TestRouter is the router's boundary table: every mount panic, then each kind
// of route against each credential, host, and header that must be refused,
// stripped, or answered with the fixed security headers.
func TestRouter(t *testing.T) {
	provider := identitytest.NewProvider(t)
	app := httptest.NewServer(nil)
	defer app.Close()
	policy, _ := authz.New(map[string][]string{"observer": {"diagnostics.read", "notes.write"}}, map[string][]string{"observers": {"observer"}}, nil, []string{"diagnostics.read"})
	sessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL, DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	router := sessions.Router()
	app.Config.Handler = router

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	for _, test := range []struct {
		mount func()
		panic string
	}{
		{func() { router.Private("/api/notes", "diagnostics.read", ok) }, `identity: router.Private("/api/notes"): a pattern needs a method, such as "GET /api/notes"`},
		{func() { router.Service("get /api/status", "diagnostics.read", ok) }, `identity: router.Service("get /api/status"): a pattern needs a method, such as "GET /api/status"`},
		{func() { router.Private("HEAD /api/notes", "diagnostics.read", ok) }, `identity: router.Private("HEAD /api/notes"): a pattern needs a method`},
		{func() { router.Public("OPTIONS /api/notes", ok) }, `identity: router.Public("OPTIONS /api/notes"): a pattern needs a method`},
		{func() { router.Private("GET\t/api/notes", "diagnostics.read", ok) }, `a pattern needs a method`},
		{func() { router.Private("GET app.example.com/api/notes", "diagnostics.read", ok) }, `identity: router.Private("GET app.example.com/api/notes"): a pattern's path starts with "/" after one space and names no host`},
		{func() { router.Public("GET  /api/notes", ok) }, `a pattern's path starts with "/"`},
		{func() { router.Private("GET /api/me", "", ok) }, `identity: router.Private("GET /api/me"): a permission is required`},
		{func() { router.Service("GET /api/status", "", ok) }, `identity: router.Service("GET /api/status"): a permission is required`},
		{func() { router.Private("GET /api/me", "diagnostics.read", nil) }, `identity: router.Private("GET /api/me"): the handler is nil`},
		{func() { router.Service("GET /api/status", "diagnostics.read", nil) }, `identity: router.Service("GET /api/status"): the handler is nil`},
		{func() { router.Public("GET /api/catalogue", nil) }, `identity: router.Public("GET /api/catalogue"): the handler is nil`},
		{func() { router.Public("POST /api/posts", ok) }, `identity: router.Public("POST /api/posts"): public routes are GET only`},
		{func() { router.Public("GET /api/catalogue", ok, identity.PublicOptions{}, identity.PublicOptions{}) }, `identity: router.Public("GET /api/catalogue"): pass at most one PublicOptions`},
		{func() { router.Public("GET /probes/", ok, identity.PublicOptions{Probe: true}) }, `identity: router.Public("GET /probes/"): a probe serves one path, never a subtree`},
		{func() { router.Public("GET /probes/{rest...}", ok, identity.PublicOptions{Probe: true}) }, `never a subtree`},
		{func() { sessions.Router() }, `identity: Sessions.Router called twice; mount every route on the one router`},
	} {
		func() {
			defer func() {
				if recovered := fmt.Sprint(recover()); !strings.Contains(recovered, test.panic) {
					t.Fatalf("panic %q, want %q", recovered, test.panic)
				}
			}()
			test.mount()
		}()
	}

	// Each public route logs one line at mount, flagging a subtree.
	var mountLog bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&mountLog, nil)))
	router.Public("GET /public/echo", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, canHijack := w.(http.Hijacker)
		_, canUnwrap := w.(interface{ Unwrap() http.ResponseWriter })
		_ = json.NewEncoder(w).Encode(map[string]any{"cookie": r.Header.Get("Cookie"), "authorization": r.Header.Get("Authorization"), "proxy_authorization": r.Header.Get("Proxy-Authorization"), "hijack": canHijack || canUnwrap})
	}))
	router.Public("GET /public/reads-identity", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { identity.FromContext(r.Context()) }))
	router.Public("GET /public/cached", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Cache-Control", "max-age=60") }))
	router.Public("GET /public/shared", ok, identity.PublicOptions{CrossOrigin: true})
	router.Public("GET /files/", ok)
	router.Public("GET /health", ok, identity.PublicOptions{Probe: true})
	slog.SetDefault(defaultLogger)
	for _, line := range []string{
		`"msg":"AppKit public route","pattern":"GET /public/echo","subtree":false,"probe":false,"cross_origin":false`,
		`"msg":"AppKit public route","pattern":"GET /public/shared","subtree":false,"probe":false,"cross_origin":true`,
		`"msg":"AppKit public route","pattern":"GET /files/","subtree":true,"probe":false,"cross_origin":false`,
		`"msg":"AppKit public route","pattern":"GET /health","subtree":false,"probe":true,"cross_origin":false`,
	} {
		if !strings.Contains(mountLog.String(), line) {
			t.Fatalf("mount log missing %s in:\n%s", line, mountLog.String())
		}
	}
	if count := strings.Count(mountLog.String(), "AppKit public route"); count != 6 {
		t.Fatalf("%d public route lines, want 6", count)
	}

	readJSON := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input map[string]string
		if err := api.ReadJSON(r, &input); err != nil {
			api.WriteError(w, r, err)
		}
	})
	router.Private("GET /private", "diagnostics.read", ok)
	router.Private("POST /private", "diagnostics.read", ok)
	router.Private("GET /private/notes", "notes.write", ok)
	router.Private("POST /private/body", "diagnostics.read", readJSON)
	router.Private("POST /private/upload", "diagnostics.read", api.LimitBody(4<<20, readJSON))
	router.Service("GET /service", "diagnostics.read", ok)

	alice := identitytest.User{Subject: "alice", Groups: []string{"observers"}}
	cookie := provider.SignIn(t, app.URL, alice)
	leaving := provider.SignIn(t, app.URL, identitytest.User{Subject: "bob", Groups: []string{"observers"}})
	_, key := provider.CreateKey(t, app.URL, cookie, "ci", "diagnostics.read")
	token := provider.AccessToken(t, alice)
	overDefault := `{"pad":"` + strings.Repeat("p", api.DefaultBodyLimit) + `"}`
	fixed := map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "same-origin", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "frame-ancestors 'none'", "X-Frame-Options": "DENY", "Strict-Transport-Security": ""}
	sameOrigin := map[string]string{"Origin": app.URL, "Content-Type": "application/json"}
	for _, test := range []struct {
		name         string
		method, path string
		host         string // empty is the app's own
		cookie       *http.Cookie
		headers      map[string]string
		body         string
		status       int
		contains     string
		want         map[string]string // response headers; an empty value means absent
	}{
		{"mux 404 carries the fixed headers", "GET", "/nothing", "", nil, nil, "", 404, "", fixed},
		{"mux 405 carries the fixed headers", "POST", "/public/echo", "", nil, nil, "", 405, "", fixed},
		{"auth route keeps its method", "POST", "/auth/login", "", nil, nil, "", 405, "", fixed},
		{"public strips every credential", "GET", "/public/echo", "", cookie, map[string]string{"Authorization": "Basic Zm9vOmJhcg==", "Proxy-Authorization": "Basic Zm9vOmJhcg=="}, "", 200, `{"authorization":"","cookie":"","hijack":false,"proxy_authorization":""}`, fixed},
		{"public refuses a bearer credential", "GET", "/public/echo", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 400, `{"error":"This route is public and takes no credentials; check the path."}`, nil},
		{"public refuses an upgrade", "GET", "/public/echo", "", nil, map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, "", 400, `"error"`, nil},
		{"public keeps the host check", "GET", "/public/echo", "wrong.example", nil, nil, "", 421, "This application is served at " + app.URL, nil},
		{"probe serves any host", "GET", "/health", "wrong.example", nil, nil, "", 200, "ok", fixed},
		{"probe drops a credential silently", "GET", "/health", "", cookie, map[string]string{"Authorization": "Bearer " + token}, "", 200, "ok", nil},
		{"public handler replaces no-store", "GET", "/public/cached", "", nil, nil, "", 200, "", map[string]string{"Cache-Control": "max-age=60"}},
		{"public without cross-origin", "GET", "/public/echo", "", nil, nil, "", 200, "", map[string]string{"Access-Control-Allow-Origin": ""}},
		{"public with cross-origin", "GET", "/public/shared", "", nil, map[string]string{"Origin": "https://shop.example"}, "", 200, "ok", map[string]string{"Access-Control-Allow-Origin": "*"}},
		{"public subtree", "GET", "/files/a/b", "", nil, nil, "", 200, "ok", nil},
		{"private signed out page request", "GET", "/private", "", nil, map[string]string{"Accept": "text/html"}, "", 401, `{"error":"Sign in required."}`, map[string]string{"Location": "", "Content-Type": "application/json"}},
		{"private with a session", "GET", "/private", "", cookie, nil, "", 200, "ok", fixed},
		{"private with a key", "GET", "/private", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 200, "ok", nil},
		{"private key without the permission", "GET", "/private/notes", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 403, `"error"`, nil},
		{"private cross-origin post", "POST", "/private", "", cookie, map[string]string{"Origin": "https://evil.example"}, "", 403, `"error"`, nil},
		{"private refuses an access token", "GET", "/private", "", nil, map[string]string{"Authorization": "Bearer " + token}, "", 401, `"error"`, nil},
		{"private keeps the host check", "GET", "/private", "wrong.example", cookie, nil, "", 421, "", nil},
		{"service with an access token on any host", "GET", "/service", "wrong.example", nil, map[string]string{"Authorization": "Bearer " + token}, "", 200, "ok", fixed},
		{"service refuses a session", "GET", "/service", "", cookie, nil, "", 401, `"error"`, nil},
		{"service refuses a key", "GET", "/service", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 401, `"error"`, nil},
		{"body over the default limit", "POST", "/private/body", "", cookie, sameOrigin, overDefault, 413, `"error"`, nil},
		{"route limit raises the default", "POST", "/private/upload", "", cookie, sameOrigin, overDefault, 200, "", nil},
		// Under no-referrer Chrome sends Origin: null on a same-origin form post, which sign-out refuses.
		{"page sets a same-origin referrer policy", "GET", "/public/echo", "", nil, nil, "", 200, "", map[string]string{"Referrer-Policy": "same-origin"}},
		{"form sign-out from a page served by the router", "POST", "/auth/logout", "", leaving, map[string]string{"Origin": app.URL, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"}, "", 303, "", map[string]string{"Location": "/"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(test.method, app.URL+test.path, strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			if test.host != "" {
				request.Host = test.host
			}
			if test.cookie != nil {
				request.AddCookie(test.cookie)
			}
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != test.status || !strings.Contains(string(body), test.contains) {
				t.Fatalf("%d %q, want %d containing %q", response.StatusCode, body, test.status, test.contains)
			}
			for name, value := range test.want {
				if got := response.Header.Get(name); got != value {
					t.Fatalf("%s: %q, want %q", name, got, value)
				}
			}
		})
	}

	// A public handler that reads the identity fails loudly instead of answering.
	request := httptest.NewRequest("GET", "/public/reads-identity", nil)
	request.Host = mustHost(t, app.URL)
	request.AddCookie(cookie)
	func() {
		defer func() {
			if recovered := fmt.Sprint(recover()); recovered != "identity: a public route's handler read the identity; public handlers serve everyone the same" {
				t.Fatalf("public identity read: %q", recovered)
			}
		}()
		router.ServeHTTP(httptest.NewRecorder(), request)
	}()
}

func mustHost(t *testing.T, origin string) string {
	t.Helper()
	parsed, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}
