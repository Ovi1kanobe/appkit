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
	"time"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/config"
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
	policy, _ := authz.New(map[string][]string{"observer": {"diagnostics.read", "notes.write"}, "writer": {"notes.write"}}, map[string][]string{"observers": {"observer"}, "writers": {"writer"}}, map[string][]string{"monitor": {"observer"}}, []string{"diagnostics.read"})
	sessions, err := identity.NewSessions(context.Background(), identity.SessionConfig{Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: app.URL, DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	// A small limit, so the 413 case shows the config's value is the one applied.
	const bodyLimit = 64 << 10
	// Each rate limit row names the CLIENT_ADDRESS rule public limits read.
	clientAddress := mustClientAddress(t, "header:X-Forwarded-For")
	router := sessions.Router(identity.RouterConfig{BodyLimit: bodyLimit, ClientAddress: func(request *http.Request) string { return clientAddress(request) }})
	app.Config.Handler = router
	// Rate limits read this clock, so the refill case advances it instead of sleeping.
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	identity.SetRouterClock(router, func() time.Time { return clock })

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
		{func() { router.Public("POST /api/posts", ok) }, `identity: router.Public("POST /api/posts"): a write names its Origin, identity.SameOrigin or identity.AnyOrigin`},
		{func() { router.Public("DELETE /api/posts/{id}", ok, identity.PublicOptions{CrossOrigin: true}) }, `identity: router.Public("DELETE /api/posts/{id}"): a write names its Origin`},
		{func() { router.Public("POST /api/posts", ok, identity.PublicOptions{Origin: identity.OriginPolicy(7)}) }, `identity: router.Public("POST /api/posts"): Origin is identity.SameOrigin or identity.AnyOrigin`},
		{func() { router.Public("GET /api/catalogue", ok, identity.PublicOptions{Origin: identity.AnyOrigin}) }, `identity: router.Public("GET /api/catalogue"): Origin is for writes; a GET needs none, so remove it`},
		{func() {
			router.Public("POST /api/posts", ok, identity.PublicOptions{Origin: identity.SameOrigin, CrossOrigin: true})
		}, `identity: router.Public("POST /api/posts"): a SameOrigin write refuses every other origin, so CrossOrigin would do nothing; use identity.AnyOrigin or remove CrossOrigin`},
		{func() {
			router.Public("POST /api/posts", ok, identity.PublicOptions{Origin: identity.AnyOrigin, CrossOrigin: true, CrossOriginRequestHeaders: []string{"Content-Type", "authorization"}})
		}, `identity: router.Public("POST /api/posts"): CrossOriginRequestHeaders has Authorization, but a public route takes no credentials`},
		{func() {
			router.Public("POST /api/posts", ok, identity.PublicOptions{Origin: identity.AnyOrigin, CrossOriginRequestHeaders: []string{"Content-Type"}})
		}, `identity: router.Public("POST /api/posts"): CrossOriginRequestHeaders needs CrossOrigin: true, since only a cross-origin route answers preflights`},
		{func() {
			router.Public("POST /api/posts", ok, identity.PublicOptions{Origin: identity.AnyOrigin, CrossOrigin: true, CrossOriginRequestHeaders: []string{"Content Type"}})
		}, `identity: router.Public("POST /api/posts"): CrossOriginRequestHeaders has "Content Type", which is not a header name`},
		{func() { router.Public("GET /api/catalogue", ok, identity.PublicOptions{}, identity.PublicOptions{}) }, `identity: router.Public("GET /api/catalogue"): pass at most one PublicOptions`},
		{func() {
			router.Private("GET /api/notes", "diagnostics.read", ok, identity.PrivateOptions{}, identity.PrivateOptions{})
		}, `identity: router.Private("GET /api/notes"): pass at most one PrivateOptions`},
		{func() {
			router.Service("GET /api/status", "diagnostics.read", ok, identity.ServiceOptions{}, identity.ServiceOptions{})
		}, `identity: router.Service("GET /api/status"): pass at most one ServiceOptions`},
		{func() {
			router.Public("GET /api/catalogue", ok, identity.PublicOptions{RateLimit: identity.RateLimit{Requests: 60}})
		}, `identity: router.Public("GET /api/catalogue"): a RateLimit needs both Requests and Per above zero, such as identity.RateLimit{Requests: 60, Per: time.Minute}, or neither for no limit`},
		{func() {
			router.Private("GET /api/notes", "diagnostics.read", ok, identity.PrivateOptions{RateLimit: identity.RateLimit{Per: time.Minute}})
		}, `identity: router.Private("GET /api/notes"): a RateLimit needs both Requests and Per above zero`},
		{func() {
			router.Service("GET /api/status", "diagnostics.read", ok, identity.ServiceOptions{RateLimit: identity.RateLimit{Requests: -1, Per: time.Minute}})
		}, `identity: router.Service("GET /api/status"): a RateLimit needs both Requests and Per above zero`},
		{func() {
			router.Public("GET /api/catalogue", ok, identity.PublicOptions{RateLimit: identity.RateLimit{Requests: 60, Per: -time.Minute}})
		}, `identity: router.Public("GET /api/catalogue"): a RateLimit needs both Requests and Per above zero`},
		{func() { router.Public("GET /probes/", ok, identity.PublicOptions{Probe: true}) }, `identity: router.Public("GET /probes/"): a probe serves one path, never a subtree`},
		{func() { router.Public("GET /probes/{rest...}", ok, identity.PublicOptions{Probe: true}) }, `never a subtree`},
		{func() { router.Private("GET /auth/me", "diagnostics.read", ok) }, `identity: router.Private("GET /auth/me"): /auth/ belongs to AppKit; mount the route elsewhere`},
		{func() { router.Service("POST /auth", "diagnostics.read", ok) }, `identity: router.Service("POST /auth"): /auth/ belongs to AppKit`},
		{func() { router.Public("GET /auth/", ok) }, `identity: router.Public("GET /auth/"): /auth/ belongs to AppKit`},
		{func() { router.Private("POST /%61uth/login", "diagnostics.read", ok) }, `identity: router.Private("POST /%61uth/login"): /auth/ belongs to AppKit`},
		// A wildcard that overlaps /auth/ conflicts with AppKit's reservation, and Go's ServeMux refuses it.
		{func() { router.Private("POST /{collection}/login", "diagnostics.read", ok) }, `conflicts with pattern "POST /auth/"`},
		{func() { sessions.Router(identity.RouterConfig{}) }, `identity: Sessions.Router needs a BodyLimit above zero; pass one such as api.DefaultBodyLimit`},
		{func() { sessions.Router(identity.RouterConfig{BodyLimit: -1}) }, `identity: Sessions.Router needs a BodyLimit above zero`},
		{func() { sessions.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit}) }, `identity: Sessions.Router needs a ClientAddress; pass appKit.ClientAddress, read from CLIENT_ADDRESS`},
		{func() {
			sessions.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit, ClientAddress: mustClientAddress(t, "remote")})
		}, `identity: Sessions.Router called twice; mount every route on the one router`},
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
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, canHijack := w.(http.Hijacker)
		_, canUnwrap := w.(interface{ Unwrap() http.ResponseWriter })
		_, canFlush := w.(http.Flusher)
		_ = json.NewEncoder(w).Encode(map[string]any{"cookie": r.Header.Get("Cookie"), "authorization": r.Header.Get("Authorization"), "proxy_authorization": r.Header.Get("Proxy-Authorization"), "user": r.URL.User.String(), "hijack": canHijack || canUnwrap, "flush": canFlush})
	})
	router.Public("GET /public/echo", echo)
	router.Public("GET /public/reads-identity", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { identity.FromContext(r.Context()) }))
	router.Public("GET /public/cached", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Cache-Control", "max-age=60") }))
	router.Public("GET /public/shared", ok, identity.PublicOptions{CrossOrigin: true})
	router.Public("GET /files/", ok)
	router.Public("GET /health", echo, identity.PublicOptions{Probe: true})
	router.Public("GET /public/limited", ok, identity.PublicOptions{CrossOrigin: true, RateLimit: identity.RateLimit{Requests: 2, Per: time.Minute}})
	// A table of two callers, so three fill it past its cap.
	defaultKeys := identity.SetRouterRateLimitKeys(router, 2)
	router.Public("GET /public/capped", ok, identity.PublicOptions{RateLimit: identity.RateLimit{Requests: 1, Per: time.Minute}})
	identity.SetRouterRateLimitKeys(router, defaultKeys)
	// Writes, one per method, and one path with a cross-origin read and writes
	// for the preflight rows: a JSON POST from any origin, limited to one a
	// minute, and a PUT without CrossOrigin, which only the app's own pages
	// may send.
	anyOrigin := identity.PublicOptions{Origin: identity.AnyOrigin}
	router.Public("POST /public/write", echo, anyOrigin)
	router.Public("PUT /public/write", ok, anyOrigin)
	router.Public("PATCH /public/write", ok, anyOrigin)
	router.Public("DELETE /public/write", ok, anyOrigin)
	router.Public("POST /public/same-origin", ok, identity.PublicOptions{Origin: identity.SameOrigin})
	router.Public("POST /public/same-origin-limited", ok, identity.PublicOptions{Origin: identity.SameOrigin, RateLimit: identity.RateLimit{Requests: 1, Per: time.Minute}})
	router.Public("POST /public/reads-identity", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { identity.FromContext(r.Context()) }), anyOrigin)
	router.Public("GET /public/cross-origin", ok, identity.PublicOptions{CrossOrigin: true})
	router.Public("POST /public/cross-origin", ok, identity.PublicOptions{Origin: identity.AnyOrigin, CrossOrigin: true, CrossOriginRequestHeaders: []string{"content-type"}, RateLimit: identity.RateLimit{Requests: 1, Per: time.Minute}})
	router.Public("PUT /public/cross-origin", ok, identity.PublicOptions{Origin: identity.SameOrigin})
	slog.SetDefault(defaultLogger)
	for _, line := range []string{
		`"msg":"AppKit public route","pattern":"POST /public/write","subtree":false,"probe":false,"origin":"any-origin","cross_origin":false,"cross_origin_request_headers":[],"rate_limit":""`,
		`"msg":"AppKit public route","pattern":"POST /public/same-origin","subtree":false,"probe":false,"origin":"same-origin"`,
		`"msg":"AppKit public route","pattern":"POST /public/cross-origin","subtree":false,"probe":false,"origin":"any-origin","cross_origin":true,"cross_origin_request_headers":["Content-Type"],"rate_limit":"1/1m0s"`,
		`"msg":"AppKit public route","pattern":"GET /public/echo","subtree":false,"probe":false,"origin":"","cross_origin":false,"cross_origin_request_headers":[],"rate_limit":""`,
		`"msg":"AppKit public route","pattern":"GET /public/limited","subtree":false,"probe":false,"origin":"","cross_origin":true,"cross_origin_request_headers":[],"rate_limit":"2/1m0s"`,
		`"msg":"AppKit public route","pattern":"GET /public/shared","subtree":false,"probe":false,"origin":"","cross_origin":true`,
		`"msg":"AppKit public route","pattern":"GET /files/","subtree":true,"probe":false,"origin":"","cross_origin":false`,
		`"msg":"AppKit public route","pattern":"GET /health","subtree":false,"probe":true,"origin":"","cross_origin":false`,
	} {
		if !strings.Contains(mountLog.String(), line) {
			t.Fatalf("mount log missing %s in:\n%s", line, mountLog.String())
		}
	}
	if count := strings.Count(mountLog.String(), "AppKit public route"); count != 18 {
		t.Fatalf("%d public route lines, want 18", count)
	}
	// authz refuses the public subject as a client ID, under its own copy of
	// the name, since identity imports authz; this keeps the two in step.
	if _, err := authz.New(map[string][]string{"reader": {"notes.read"}}, nil, map[string][]string{identity.PublicSubject: {"reader"}}, nil); err == nil {
		t.Fatalf("authz accepted %q as a client ID", identity.PublicSubject)
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
	router.Private("GET /private/limited", "diagnostics.read", ok, identity.PrivateOptions{RateLimit: identity.RateLimit{Requests: 1, Per: time.Minute}})
	router.Service("GET /service/limited", "diagnostics.read", ok, identity.ServiceOptions{RateLimit: identity.RateLimit{Requests: 1, Per: time.Minute}})

	alice := identitytest.User{Subject: "alice", Groups: []string{"observers"}}
	cookie := provider.SignIn(t, app.URL, alice)
	leaving := provider.SignIn(t, app.URL, identitytest.User{Subject: "bob", Groups: []string{"observers"}})
	_, key := provider.CreateKey(t, app.URL, cookie, "ci", "diagnostics.read")
	token := provider.AccessToken(t, alice)
	carol := provider.SignIn(t, app.URL, identitytest.User{Subject: "carol", Groups: []string{"observers"}})
	writer := provider.SignIn(t, app.URL, identitytest.User{Subject: "dave", Groups: []string{"writers"}}) // lacks diagnostics.read
	monitor := provider.ClientToken(t, "monitor", provider.ClientID)
	overLimit := `{"pad":"` + strings.Repeat("p", bodyLimit) + `"}`
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
		{"auth route keeps its method", "POST", "/auth/login", "", nil, nil, "", 405, "", map[string]string{"Allow": "GET, HEAD", "Cache-Control": "no-store"}},
		{"auth route keeps a post-only method", "GET", "/auth/logout", "", nil, nil, "", 405, "", map[string]string{"Allow": "POST"}},
		{"no auth route there", "POST", "/auth/nothing", "", nil, nil, "", 404, "", fixed},
		{"public strips every credential", "GET", "/public/echo", "", cookie, map[string]string{"Authorization": "Basic Zm9vOmJhcg==", "Proxy-Authorization": "Basic Zm9vOmJhcg=="}, "", 200, `{"authorization":"","cookie":"","flush":true,"hijack":false,"proxy_authorization":"","user":""}`, fixed},
		{"public refuses a bearer credential", "GET", "/public/echo", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 400, `{"error":"This route is public and takes no credentials; check the path."}`, nil},
		{"public refuses an upgrade", "GET", "/public/echo", "", nil, map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, "", 400, `{"error":"This route is public and cannot be upgraded; check the path."}`, nil},
		{"public keeps the host check", "GET", "/public/echo", "wrong.example", nil, nil, "", 421, "This application is served at " + app.URL, nil},
		{"probe serves any host", "GET", "/health", "wrong.example", nil, nil, "", 200, `"cookie":""`, fixed},
		{"probe drops a credential silently", "GET", "/health", "", cookie, map[string]string{"Authorization": "Bearer " + token}, "", 200, `{"authorization":"","cookie":"",`, nil},
		{"public handler replaces no-store", "GET", "/public/cached", "", nil, nil, "", 200, "", map[string]string{"Cache-Control": "max-age=60"}},
		{"public without cross-origin", "GET", "/public/echo", "", nil, nil, "", 200, "", map[string]string{"Access-Control-Allow-Origin": ""}},
		{"public with cross-origin", "GET", "/public/shared", "", nil, map[string]string{"Origin": "https://shop.example"}, "", 200, "ok", map[string]string{"Access-Control-Allow-Origin": "*"}},
		{"cross-origin refusal is readable", "GET", "/public/shared", "", nil, map[string]string{"Origin": "https://shop.example", "Authorization": "Bearer " + key}, "", 400, `{"error":"This route is public and takes no credentials; check the path."}`, map[string]string{"Access-Control-Allow-Origin": "*"}},
		{"cross-origin wrong host is readable", "GET", "/public/shared", "wrong.example", nil, map[string]string{"Origin": "https://shop.example"}, "", 421, "This application is served at " + app.URL, map[string]string{"Access-Control-Allow-Origin": "*"}},
		{"public subtree", "GET", "/files/a/b", "", nil, nil, "", 200, "ok", nil},
		{"private signed out page request", "GET", "/private", "", nil, map[string]string{"Accept": "text/html"}, "", 401, `{"error":"Sign in required."}`, map[string]string{"Location": "", "Content-Type": "application/json"}},
		{"private with a session", "GET", "/private", "", cookie, nil, "", 200, "ok", fixed},
		{"private with a key", "GET", "/private", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 200, "ok", nil},
		{"private key without the permission", "GET", "/private/notes", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 403, `{"error":"You don't have permission for this."}`, nil},
		{"private cross-origin post", "POST", "/private", "", cookie, map[string]string{"Origin": "https://evil.example"}, "", 403, `{"error":"Same-origin request required."}`, nil},
		{"private refuses an access token", "GET", "/private", "", nil, map[string]string{"Authorization": "Bearer " + token}, "", 401, `{"error":"Key not accepted."}`, nil},
		{"private keeps the host check", "GET", "/private", "wrong.example", cookie, nil, "", 421, "", nil},
		{"service with an access token on any host", "GET", "/service", "wrong.example", nil, map[string]string{"Authorization": "Bearer " + token}, "", 200, "ok", fixed},
		{"service refuses a session", "GET", "/service", "", cookie, nil, "", 401, `{"error":"Sign in required."}`, nil},
		{"service refuses a key", "GET", "/service", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 401, `{"error":"Sign in required."}`, nil},
		{"body over the router's limit", "POST", "/private/body", "", cookie, sameOrigin, overLimit, 413, `{"error":"The request is too large."}`, nil},
		{"route limit raises the router's", "POST", "/private/upload", "", cookie, sameOrigin, overLimit, 200, "", nil},
		// Under no-referrer Chrome sends Origin: null on a same-origin form post, which sign-out refuses.
		{"page sets a same-origin referrer policy", "GET", "/public/echo", "", nil, nil, "", 200, "", map[string]string{"Referrer-Policy": "same-origin"}},
		{"form sign-out from a page served by the router", "POST", "/auth/logout", "", leaving, map[string]string{"Origin": app.URL, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"}, "", 303, "", map[string]string{"Location": "/"}},
		{"public POST serves", "POST", "/public/write", "", nil, nil, "", 200, `"cookie":""`, fixed},
		{"public PUT serves", "PUT", "/public/write", "", nil, nil, "", 200, "ok", nil},
		{"public PATCH serves", "PATCH", "/public/write", "", nil, nil, "", 200, "ok", nil},
		{"public DELETE serves", "DELETE", "/public/write", "", nil, nil, "", 200, "ok", nil},
		{"public write strips every credential", "POST", "/public/write", "", cookie, map[string]string{"Authorization": "Basic Zm9vOmJhcg==", "Proxy-Authorization": "Basic Zm9vOmJhcg=="}, "", 200, `{"authorization":"","cookie":"","flush":true,"hijack":false,"proxy_authorization":"","user":""}`, nil},
		{"public write refuses a bearer credential", "POST", "/public/write", "", nil, map[string]string{"Authorization": "Bearer " + key}, "", 400, `{"error":"This route is public and takes no credentials; check the path."}`, nil},
		{"cross-site form post to an AnyOrigin write served", "POST", "/public/write", "", nil, map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site", "Content-Type": "application/x-www-form-urlencoded"}, "text=hi", 200, `"cookie":""`, map[string]string{"Access-Control-Allow-Origin": ""}},
		{"cross-site form post to a SameOrigin write refused", "POST", "/public/same-origin", "", nil, map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site", "Content-Type": "application/x-www-form-urlencoded"}, "text=hi", 403, `{"error":"Same-origin request required."}`, nil},
		{"same-origin post to a SameOrigin write served", "POST", "/public/same-origin", "", nil, map[string]string{"Origin": app.URL, "Sec-Fetch-Site": "same-origin"}, "", 200, "ok", nil},
		{"SameOrigin write refuses a client that is no browser", "POST", "/public/same-origin", "", nil, nil, "", 403, `{"error":"Same-origin request required."}`, nil},
		{"SameOrigin write keeps the host check", "POST", "/public/same-origin", "wrong.example", nil, map[string]string{"Origin": app.URL, "Sec-Fetch-Site": "same-origin"}, "", 421, "This application is served at " + app.URL, nil},
		// In order: the cross-site refusal spends none of the route's one token a minute.
		{"cross-site post refused before the rate limit", "POST", "/public/same-origin-limited", "", nil, map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, "", 403, `{"error":"Same-origin request required."}`, nil},
		{"same-origin post after a cross-site refusal served", "POST", "/public/same-origin-limited", "", nil, map[string]string{"Origin": app.URL, "Sec-Fetch-Site": "same-origin"}, "", 200, "ok", nil},
		{"same-origin post over the limit", "POST", "/public/same-origin-limited", "", nil, map[string]string{"Origin": app.URL, "Sec-Fetch-Site": "same-origin"}, "", 429, `{"error":"Too many requests; try again later."}`, nil},
		// Preflights are answered before any route. In order: none of the rows
		// up to "cross-origin write after its preflights served" may spend the
		// POST's one token a minute, which that row then spends.
		{"preflight asking for HEAD", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "HEAD"}, "", 204, "", map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, HEAD, POST", "Access-Control-Allow-Headers": ""}},
		{"preflight on a path that does not exist", "OPTIONS", "/public/nothing", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "GET"}, "", 403, `{"error":"This route does not accept requests from other origins."}`, map[string]string{"Access-Control-Allow-Origin": ""}},
		{"preflight for a cross-origin write", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}, "", 204, "", map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, HEAD, POST", "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers", "Access-Control-Allow-Credentials": "", "Access-Control-Max-Age": "", "Cache-Control": "no-store"}},
		{"preflight for a header the route does not list", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,x-trace"}, "", 403, `{"error":"This route does not accept the X-Trace header from other origins."}`, map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": ""}},
		{"preflight for a SameOrigin write from another origin", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "PUT"}, "", 403, `{"error":"This route does not accept requests from other origins."}`, map[string]string{"Access-Control-Allow-Origin": ""}},
		{"preflight keeps the host check", "OPTIONS", "/public/cross-origin", "wrong.example", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "POST"}, "", 421, "This application is served at " + app.URL, map[string]string{"Access-Control-Allow-Origin": "*"}},
		{"preflight for a private route", "OPTIONS", "/private", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "POST"}, "", 403, `{"error":"This route does not accept requests from other origins."}`, map[string]string{"Access-Control-Allow-Origin": ""}},
		{"preflight for a public route without cross-origin", "OPTIONS", "/public/write", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "POST"}, "", 403, `{"error":"This route does not accept requests from other origins."}`, map[string]string{"Access-Control-Allow-Origin": ""}},
		{"preflight without an Origin", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Access-Control-Request-Method": "POST"}, "", 400, `{"error":"A preflight names one Origin."}`, map[string]string{"Access-Control-Allow-Origin": ""}},
		{"preflight with a lowercase method", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "post"}, "", 400, `{"error":"A preflight names one method in Access-Control-Request-Method, one of HEAD, GET, POST, PUT, PATCH, DELETE."}`, nil},
		{"preflight with an unknown method", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "TRACE"}, "", 400, `Access-Control-Request-Method`, nil},
		{"preflight with a malformed header list", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,,x-trace"}, "", 400, `{"error":"A preflight lists header names, separated by commas, in Access-Control-Request-Headers."}`, nil},
		{"cross-origin write after its preflights served", "POST", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Content-Type": "application/json"}, `{}`, 200, "ok", map[string]string{"Access-Control-Allow-Origin": "*"}},
		{"cross-origin write over its limit is readable", "POST", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example", "Content-Type": "application/json"}, `{}`, 429, `{"error":"Too many requests; try again later."}`, map[string]string{"Access-Control-Allow-Origin": "*", "Access-Control-Expose-Headers": "Retry-After"}},
		{"OPTIONS without a request method falls through to the route table", "OPTIONS", "/public/cross-origin", "", nil, map[string]string{"Origin": "https://shop.example"}, "", 405, "", map[string]string{"Access-Control-Allow-Origin": "", "Access-Control-Allow-Methods": ""}},
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

	// Rate limits, in order against one clock: a public route counts per client
	// address as the row's CLIENT_ADDRESS rule reads it, a private or service
	// route per identity subject after authentication, and Per refills.
	tooMany := `{"error":"Too many requests; try again later."}`
	forwarded := func(address string) map[string]string { return map[string]string{"X-Forwarded-For": address} }
	for _, test := range []struct {
		name          string
		clientAddress string // the CLIENT_ADDRESS rule from this row on; empty keeps the last
		path          string
		cookie        *http.Cookie
		headers       map[string]string
		advance       time.Duration // moves the clock before the request
		status        int
		contains      string
		want          map[string]string // response headers; an empty value means absent
	}{
		{"public under the limit served", "header:X-Forwarded-For", "/public/limited", nil, forwarded("203.0.113.7"), 0, 200, "ok", map[string]string{"Retry-After": ""}},
		{"public up to the limit served", "", "/public/limited", nil, forwarded("203.0.113.7"), 0, 200, "ok", nil},
		{"public after the limit 429 with Retry-After", "", "/public/limited", nil, forwarded("203.0.113.7"), 0, 429, tooMany, map[string]string{"Retry-After": "30", "Access-Control-Allow-Origin": "*", "Access-Control-Expose-Headers": "Retry-After", "Cache-Control": "no-store"}},
		{"public forged earlier forwarded entry changes nothing", "", "/public/limited", nil, forwarded("198.51.100.1, 203.0.113.7"), 0, 429, tooMany, nil},
		{"public 429 comes before the Host check", "", "/public/limited", nil, map[string]string{"X-Forwarded-For": "203.0.113.7", "Host": "wrong.example"}, 0, 429, tooMany, nil},
		{"public second address unaffected", "", "/public/limited", nil, forwarded("203.0.113.8"), 0, 200, "ok", nil},
		{"public named single-valued header", "header:CF-Connecting-IP", "/public/limited", nil, map[string]string{"CF-Connecting-IP": "203.0.113.9", "X-Forwarded-For": "203.0.113.7"}, 0, 200, "ok", nil},
		{"public remote ignores forwarded headers", "remote", "/public/limited", nil, forwarded("203.0.113.7"), 0, 200, "ok", nil},
		{"public remote up to the limit", "", "/public/limited", nil, nil, 0, 200, "ok", nil},
		{"public remote after the limit", "", "/public/limited", nil, nil, 0, 429, tooMany, nil},
		{"public refilled after Per", "header:X-Forwarded-For", "/public/limited", nil, forwarded("203.0.113.7"), time.Minute, 200, "ok", nil},
		{"public IPv6 client served", "", "/public/limited", nil, forwarded("2001:db8:1:2::1"), 0, 200, "ok", nil},
		{"public IPv6 client rotating within its /64 served once more", "", "/public/limited", nil, forwarded("2001:db8:1:2::abcd"), 0, 200, "ok", nil},
		{"public IPv6 /64 shares one bucket", "", "/public/limited", nil, forwarded("[2001:db8:1:2:ffff::9]:443"), 0, 429, tooMany, nil},
		{"public another IPv6 /64 unaffected", "", "/public/limited", nil, forwarded("2001:db8:1:3::1"), 0, 200, "ok", nil},
		{"public capped table first caller", "", "/public/capped", nil, forwarded("203.0.113.10"), 0, 200, "ok", nil},
		{"public capped table second caller", "", "/public/capped", nil, forwarded("203.0.113.11"), 0, 200, "ok", nil},
		{"public capped table full still serves a new caller", "", "/public/capped", nil, forwarded("203.0.113.12"), 0, 200, "ok", nil},
		{"public capped table evicted the oldest caller", "", "/public/capped", nil, forwarded("203.0.113.10"), 0, 200, "ok", nil},
		{"public capped table kept the new caller", "", "/public/capped", nil, forwarded("203.0.113.12"), 0, 429, tooMany, nil},
		{"private unauthenticated flood answers 401", "", "/private/limited", nil, nil, 0, 401, `{"error":"Sign in required."}`, nil},
		{"private unauthenticated flood still 401", "", "/private/limited", nil, nil, 0, 401, `{"error":"Sign in required."}`, nil},
		{"private flood spent none of a person's tokens", "", "/private/limited", cookie, nil, 0, 200, "ok", nil},
		{"private key shares its person's bucket", "", "/private/limited", nil, map[string]string{"Authorization": "Bearer " + key}, 0, 429, tooMany, map[string]string{"Retry-After": "60"}},
		{"private second person has their own bucket", "", "/private/limited", carol, nil, 0, 200, "ok", nil},
		{"private without the permission spends a token", "", "/private/limited", writer, nil, 0, 403, `{"error":"You don't have permission for this."}`, nil},
		{"private 429 comes before the permission check", "", "/private/limited", writer, nil, 0, 429, tooMany, nil},
		{"service unauthenticated answers 401", "", "/service/limited", nil, nil, 0, 401, `{"error":"Sign in required."}`, nil},
		{"service under its limit", "", "/service/limited", nil, map[string]string{"Authorization": "Bearer " + token}, 0, 200, "ok", nil},
		{"service after its limit", "", "/service/limited", nil, map[string]string{"Authorization": "Bearer " + token}, 0, 429, tooMany, map[string]string{"Retry-After": "60"}},
		{"service application has its own bucket", "", "/service/limited", nil, map[string]string{"Authorization": "Bearer " + monitor}, 0, 200, "ok", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.clientAddress != "" {
				clientAddress = mustClientAddress(t, test.clientAddress)
			}
			clock = clock.Add(test.advance)
			request := httptest.NewRequest("GET", test.path, nil)
			request.Host = mustHost(t, app.URL)
			if host, found := test.headers["Host"]; found {
				request.Host = host // a Host header row sets the request's host, which Go keeps outside Header
			}
			if test.cookie != nil {
				request.AddCookie(test.cookie)
			}
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("%d %q, want %d containing %q", response.Code, response.Body.String(), test.status, test.contains)
			}
			for name, value := range test.want {
				if got := response.Header().Get(name); got != value {
					t.Fatalf("%s: %q, want %q", name, got, value)
				}
			}
		})
	}

	// An absolute-form request URL's user:password@ never reaches a public handler.
	withUserinfo := httptest.NewRequest("GET", "http://user:secret@"+mustHost(t, app.URL)+"/public/echo", nil)
	echoed := httptest.NewRecorder()
	router.ServeHTTP(echoed, withUserinfo)
	if echoed.Code != 200 || !strings.Contains(echoed.Body.String(), `"user":""`) {
		t.Fatalf("userinfo reached the public handler: %d %s", echoed.Code, echoed.Body.String())
	}

	// A preflight with two Origin headers is malformed.
	twoOrigins := httptest.NewRequest("OPTIONS", "/public/cross-origin", nil)
	twoOrigins.Host = mustHost(t, app.URL)
	twoOrigins.Header.Add("Origin", "https://shop.example")
	twoOrigins.Header.Add("Origin", "https://other.example")
	twoOrigins.Header.Set("Access-Control-Request-Method", "POST")
	refused := httptest.NewRecorder()
	router.ServeHTTP(refused, twoOrigins)
	if refused.Code != 400 || strings.TrimSpace(refused.Body.String()) != `{"error":"A preflight names one Origin."}` || refused.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("two-origin preflight: %d %q", refused.Code, refused.Body.String())
	}

	// A public handler that reads the identity fails loudly instead of
	// answering, a write's as a read's.
	for _, method := range []string{"GET", "POST"} {
		request := httptest.NewRequest(method, "/public/reads-identity", nil)
		request.Host = mustHost(t, app.URL)
		request.AddCookie(cookie)
		func() {
			defer func() {
				if recovered := fmt.Sprint(recover()); recovered != "identity: a public route's handler read the identity; a public answer is independent of any identity, and a public write records identity.PublicSubject" {
					t.Fatalf("public %s identity read: %q", method, recovered)
				}
			}()
			router.ServeHTTP(httptest.NewRecorder(), request)
		}()
	}
}

func mustHost(t *testing.T, origin string) string {
	t.Helper()
	parsed, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

// mustClientAddress parses a CLIENT_ADDRESS value as config does, trusting
// 192.0.2.1, the connection address httptest.NewRequest gives a request.
func mustClientAddress(t testing.TB, value string) func(*http.Request) string {
	t.Helper()
	clientAddress, err := config.ParseClientAddress(value, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	return clientAddress
}
