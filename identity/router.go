package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/Ovi1kanobe/appkit/api"
)

// Router is an application's one route table and its HTTP handler. Every
// route is mounted through Private, Service, or Public, so each line says
// what guards it; AppKit's own /auth/ routes are already on it. It caps every
// request body at its config's BodyLimit, and an api.LimitBody on a mounted
// handler raises or lowers that for its route.
type Router struct {
	sessions *Sessions
	mux      *http.ServeMux
	handler  http.Handler
}

// RouterConfig configures the router. Every field is required, so what it
// does is written on the line that makes it.
type RouterConfig struct {
	// BodyLimit caps every request body, in bytes; api.DefaultBodyLimit suits
	// JSON. A route that needs another limit wraps its handler in
	// api.LimitBody.
	BodyLimit int64
}

// PublicOptions changes how Public serves one route. The zero value is right
// for every public route but health.
type PublicOptions struct {
	// Probe serves any Host, for a health check a load balancer reaches by
	// address, and drops any credential silently instead of refusing it. It
	// is for one path, never a subtree.
	Probe bool
	// CrossOrigin lets a page on any origin read the response, with
	// Access-Control-Allow-Origin: *. Public routes are GET only and take no
	// credentials, so no preflight is involved.
	CrossOrigin bool
}

// routeMethods are the methods a route may name, uppercase as Go's ServeMux
// matches them. A GET route also answers HEAD.
var routeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// publicContextKey marks a public route's request, so FromContext panics on it.
type publicContextKey struct{}

// Router returns the application's router with AppKit's auth routes mounted.
// It is called once: a second call panics, so no route lives anywhere else.
// A BodyLimit of zero or less panics, rather than meaning a hidden default.
func (s *Sessions) Router(config RouterConfig) *Router {
	if config.BodyLimit <= 0 {
		panic("identity: Sessions.Router needs a BodyLimit above zero; pass one such as api.DefaultBodyLimit")
	}
	s.mu.Lock()
	routed := s.routed
	s.routed = true
	s.mu.Unlock()
	if routed {
		panic("identity: Sessions.Router called twice; mount every route on the one router")
	}
	router := &Router{sessions: s, mux: http.NewServeMux()}
	router.handler = api.LimitBodies(config.BodyLimit, router.mux)
	s.routes(router.mux)
	return router
}

// ServeHTTP sets the fixed security headers on every response, Go's own 404
// and 405 included, then serves the route. A handler may replace
// Cache-Control, as the frontend does to cache its files.
func (router *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	header := writer.Header()
	header.Set("Cache-Control", "no-store")
	// same-origin, not no-referrer: under no-referrer Chrome sends Origin: null
	// on same-origin POSTs, which the CSRF check refuses.
	header.Set("Referrer-Policy", "same-origin")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", "frame-ancestors 'none'")
	header.Set("X-Frame-Options", "DENY")
	if router.sessions.origin.Scheme == "https" {
		header.Set("Strict-Transport-Security", "max-age=31536000")
	}
	router.handler.ServeHTTP(writer, request)
}

// Private mounts a route for people: a session cookie, or a personal key in
// a Bearer header, holding permission. Signed out it answers 401 as JSON,
// never a redirect; without the permission, 403. A browser's mutations and
// WebSocket upgrades must come from the app's origin; a key's need not. The
// request context ends when the session or key does.
func (router *Router) Private(pattern, permission string, handler http.Handler) {
	checkRoute("Private", pattern, handler)
	checkPermission("Private", pattern, permission)
	router.mux.Handle(pattern, router.sessions.require(requirePermission(permission, handler)))
}

// Service mounts a route for a caller with a Rauthy access token holding
// permission: an application's, through the client credentials grant, or a
// person's. It never accepts a session cookie or a personal key, so it skips
// the Host check, since a browser never attaches the token by itself.
// Without a valid token it answers 401; without the permission, 403.
func (router *Router) Service(pattern, permission string, handler http.Handler) {
	checkRoute("Service", pattern, handler)
	checkPermission("Service", pattern, permission)
	router.mux.Handle(pattern, router.sessions.bearer(requirePermission(permission, handler)))
}

// Public mounts a GET route anyone may read. The handler sees no cookie,
// authorization, or trailer, and no identity: FromContext panics in it,
// because a public answer is the same for everyone. A request with a Bearer
// credential answers 400, since its caller meant another route, and so does
// a WebSocket upgrade. The Host check stays unless options say Probe. Each
// public route is logged once at mount, so the log lists them.
func (router *Router) Public(pattern string, handler http.Handler, options ...PublicOptions) {
	method, path := checkRoute("Public", pattern, handler)
	if len(options) > 1 {
		panic(fmt.Sprintf("identity: router.Public(%q): pass at most one PublicOptions", pattern))
	}
	if method != http.MethodGet {
		panic(fmt.Sprintf("identity: router.Public(%q): public routes are GET only", pattern))
	}
	var option PublicOptions
	if len(options) == 1 {
		option = options[0]
	}
	subtree := strings.HasSuffix(path, "/") || strings.HasSuffix(path, "...}")
	if option.Probe && subtree {
		panic(fmt.Sprintf("identity: router.Public(%q): a probe serves one path, never a subtree; name the path, such as \"GET /api/health\"", pattern))
	}
	slog.Info("AppKit public route", "pattern", pattern, "subtree", subtree, "probe", option.Probe, "cross_origin", option.CrossOrigin)
	served := servePublic(handler, option)
	if !option.Probe {
		served = router.sessions.boundary(served)
	}
	router.mux.Handle(pattern, served)
}

// servePublic serves a public route's handler a copy of the request with
// every credential removed, through a writer that cannot hijack the
// connection.
func servePublic(handler http.Handler, option PublicOptions) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if len(request.Header.Values("Upgrade")) != 0 {
			writeError(writer, http.StatusBadRequest, "This route is public and cannot be upgraded; check the path.")
			return
		}
		if !option.Probe && isKeyRequest(request) {
			writeError(writer, http.StatusBadRequest, "This route is public and takes no credentials; check the path.")
			return
		}
		public := request.Clone(context.WithValue(request.Context(), publicContextKey{}, true))
		public.Header.Del("Cookie")
		public.Header.Del("Authorization")
		public.Header.Del("Proxy-Authorization")
		public.Trailer = nil
		public.URL.User = nil // An absolute-form request URL can carry user:password@.
		if option.CrossOrigin {
			writer.Header().Set("Access-Control-Allow-Origin", "*")
		}
		handler.ServeHTTP(publicResponseWriter{writer: writer}, public)
	})
}

// publicResponseWriter exposes the plain ResponseWriter methods and Flush, so
// a public route can stream, but neither Hijack nor Unwrap, so a public
// handler cannot take over the connection.
type publicResponseWriter struct{ writer http.ResponseWriter }

// Flush sends buffered data to the client when the underlying writer can, and
// does nothing otherwise.
func (public publicResponseWriter) Flush() {
	if flusher, ok := public.writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (public publicResponseWriter) Header() http.Header            { return public.writer.Header() }
func (public publicResponseWriter) Write(data []byte) (int, error) { return public.writer.Write(data) }
func (public publicResponseWriter) WriteHeader(status int)         { public.writer.WriteHeader(status) }

// checkRoute panics unless pattern is an uppercase method from routeMethods,
// one space, and a path with no host outside AppKit's /auth/, and handler is
// set. It returns the
// method and path.
func checkRoute(kind, pattern string, handler http.Handler) (method, path string) {
	method, path, found := strings.Cut(pattern, " ")
	if !found || !slices.Contains(routeMethods, method) {
		example := path
		if !found {
			example = pattern
		}
		panic(fmt.Sprintf("identity: router.%s(%q): a pattern needs a method, such as \"GET %s\" (one of %s)", kind, pattern, strings.TrimSpace(example), strings.Join(routeMethods, ", ")))
	}
	if !strings.HasPrefix(path, "/") {
		panic(fmt.Sprintf("identity: router.%s(%q): a pattern's path starts with \"/\" after one space and names no host, because a host-qualified pattern beats every other", kind, pattern))
	}
	if path == "/auth" || strings.HasPrefix(path, "/auth/") {
		panic(fmt.Sprintf("identity: router.%s(%q): /auth/ belongs to AppKit; mount the route elsewhere", kind, pattern))
	}
	if handler == nil {
		panic(fmt.Sprintf("identity: router.%s(%q): the handler is nil; pass the route's handler", kind, pattern))
	}
	return method, path
}

// checkPermission panics when a guarded route names no permission.
func checkPermission(kind, pattern, permission string) {
	if permission == "" {
		panic(fmt.Sprintf("identity: router.%s(%q): a permission is required", kind, pattern))
	}
}
