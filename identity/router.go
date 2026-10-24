package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/internal/httpname"
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
	// clientAddress keys public rate limits; now is the clock rate limits
	// read and rateLimitKeys how many callers each tracks, which tests
	// replace.
	clientAddress func(*http.Request) string
	now           func() time.Time
	rateLimitKeys int
}

// RouterConfig configures the router. Every field is required, so what it
// does is written on the line that makes it.
type RouterConfig struct {
	// BodyLimit caps every request body, in bytes; api.DefaultBodyLimit suits
	// JSON. A route that needs another limit wraps its handler in
	// api.LimitBody.
	BodyLimit int64
	// ClientAddress returns the address a request came from, which keys a
	// public route's RateLimit. config.AppKit reads it from CLIENT_ADDRESS.
	ClientAddress func(*http.Request) string
}

// PublicOptions changes how Public serves one route. The zero value is right
// for a GET route but health; a write, POST, PUT, PATCH, or DELETE, must name
// its Origin.
type PublicOptions struct {
	// Probe serves any Host, for a health check a load balancer reaches by
	// address, and drops any credential silently instead of refusing it. It
	// is for one path, never a subtree.
	Probe bool
	// Origin says who may submit a write: SameOrigin, only the app's own
	// pages, or AnyOrigin, a page on any site or a client that is no browser.
	// A write without it panics at mount, and so do a GET with it, since it
	// would do nothing, and SameOrigin with CrossOrigin.
	Origin OriginPolicy
	// CrossOrigin lets a page on any origin call the route and read the
	// response, with Access-Control-Allow-Origin: *, and answers its
	// preflights. No credential is ever allowed across origins.
	CrossOrigin bool
	// CrossOriginRequestHeaders are the request headers a preflight may
	// allow, matched case-insensitively; a JSON caller lists Content-Type.
	// The list is copied at mount. It needs CrossOrigin, and a name that is
	// not a header name, or Authorization, Cookie, or Proxy-Authorization,
	// panics at mount.
	CrossOriginRequestHeaders []string
	// RateLimit caps how often one client address may call the route.
	RateLimit RateLimit
}

// OriginPolicy says who may submit a public write: SameOrigin or AnyOrigin.
// Its zero value is unset, which a write refuses at mount, so each write's
// line says who may submit it.
type OriginPolicy int

const (
	// originPolicyUnset is the zero value: no policy named, which a write
	// refuses at mount.
	originPolicyUnset OriginPolicy = iota
	// SameOrigin serves a write only from the app's own pages, with the
	// same-origin check private mutations get, and answers any other origin,
	// and any client that is no browser, 403.
	SameOrigin
	// AnyOrigin serves a write from any origin, and from clients that are no
	// browser, with no origin check.
	AnyOrigin
)

// valid reports whether policy is SameOrigin or AnyOrigin.
func (policy OriginPolicy) valid() bool {
	return policy == SameOrigin || policy == AnyOrigin
}

// label names policy for the mount log: "same-origin", "any-origin", or ""
// when unset.
func (policy OriginPolicy) label() string {
	switch policy {
	case SameOrigin:
		return "same-origin"
	case AnyOrigin:
		return "any-origin"
	}
	return ""
}

// PublicSubject is the subject a public write records as its actor, such as
// the author of a note a visitor posts; a public write handler builds its
// system's actor with it, since it has no identity to read. A rule comparing
// an actor's subject with a record's never matches a public write, because
// no identity a handler sees carries it: Rauthy generates people's subjects,
// assumed never to be "public", and authz.New refuses a policy whose client
// list names "public", so the policy is the one place a collision could
// enter and it is checked at startup. A client the policy does not list
// holds no permissions and is refused 403 before any handler runs.
const PublicSubject = "public"

// PrivateOptions changes how Private serves one route. The zero value is
// the default.
type PrivateOptions struct {
	// RateLimit caps how often one person may call the route, through a
	// session or any of their keys.
	RateLimit RateLimit
}

// ServiceOptions changes how Service serves one route. The zero value is
// the default.
type ServiceOptions struct {
	// RateLimit caps how often one caller may call the route: a person, or an
	// application by its client ID.
	RateLimit RateLimit
}

// routeMethods are the methods a route may name, uppercase as Go's ServeMux
// matches them. A GET route also answers HEAD.
var routeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// writeMethods are the route methods that change something, which a public
// mount must give an Origin.
var writeMethods = []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// publicContextKey marks a public route's request, so FromContext panics on it.
type publicContextKey struct{}

// Router returns the application's router with AppKit's auth routes mounted.
// It is called once: a second call panics, so no route lives anywhere else.
// A BodyLimit of zero or less panics, rather than meaning a hidden default.
func (s *Sessions) Router(config RouterConfig) *Router {
	if config.BodyLimit <= 0 {
		panic("identity: Sessions.Router needs a BodyLimit above zero; pass one such as api.DefaultBodyLimit")
	}
	if config.ClientAddress == nil {
		panic("identity: Sessions.Router needs a ClientAddress; pass appKit.ClientAddress, read from CLIENT_ADDRESS")
	}
	s.mu.Lock()
	routed := s.routed
	s.routed = true
	s.mu.Unlock()
	if routed {
		panic("identity: Sessions.Router called twice; mount every route on the one router")
	}
	router := &Router{sessions: s, mux: http.NewServeMux(), clientAddress: config.ClientAddress, now: time.Now, rateLimitKeys: rateLimitKeys}
	router.handler = api.LimitBodies(config.BodyLimit, router.mux)
	s.routes(router.mux)
	return router
}

// ServeHTTP sets the fixed security headers on every response, Go's own 404
// and 405 included, then serves the route. A handler may replace
// Cache-Control, as the frontend does to cache its files. A CORS preflight,
// an OPTIONS request with Access-Control-Request-Method, is answered here and
// reaches no route; any other OPTIONS request is the route table's.
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
	if request.Method == http.MethodOptions && len(request.Header.Values("Access-Control-Request-Method")) != 0 {
		router.preflight(writer, request)
		return
	}
	router.handler.ServeHTTP(writer, request)
}

// Private mounts a route for people: a session cookie, or a personal key in
// a Bearer header, holding permission. Signed out it answers 401 as JSON,
// never a redirect; without the permission, 403. A browser's mutations and
// WebSocket upgrades must come from the app's origin; a key's need not. The
// request context ends when the session or key does. A RateLimit in options
// counts per person, a session and the person's keys sharing one bucket,
// after authentication and before the permission check.
func (router *Router) Private(pattern, permission string, handler http.Handler, options ...PrivateOptions) {
	checkRoute("Private", pattern, handler)
	option := oneOption("Private", pattern, "PrivateOptions", options)
	checkPermission("Private", pattern, permission)
	checkRateLimit("Private", pattern, option.RateLimit)
	router.mux.Handle(pattern, router.sessions.require(router.rateLimited(option.RateLimit, subjectKey, requirePermission(permission, handler))))
}

// Service mounts a route for a caller with a Rauthy access token holding
// permission: an application's, through the client credentials grant, or a
// person's. It never accepts a session cookie or a personal key, so it skips
// the Host check, since a browser never attaches the token by itself.
// Without a valid token it answers 401; without the permission, 403. A
// RateLimit in options counts per caller, an application under its client
// ID, after the token is verified and before the permission check.
func (router *Router) Service(pattern, permission string, handler http.Handler, options ...ServiceOptions) {
	checkRoute("Service", pattern, handler)
	option := oneOption("Service", pattern, "ServiceOptions", options)
	checkPermission("Service", pattern, permission)
	checkRateLimit("Service", pattern, option.RateLimit)
	router.mux.Handle(pattern, router.sessions.bearer(router.rateLimited(option.RateLimit, subjectKey, requirePermission(permission, handler))))
}

// Public mounts a route anyone may call, with any method. The handler sees
// no cookie, authorization, or trailer, and no identity: FromContext panics
// in it, because a public answer is independent of any identity, and a write
// records PublicSubject as its actor. A request with a Bearer credential
// answers 400, since its caller meant another route, and so does a WebSocket
// upgrade. The Host check stays unless options say Probe. A write names its
// Origin in options, and SameOrigin refuses another origin with 403 before
// anything else, so a cross-site request spends no rate limit token. A
// RateLimit counts per client address, as RouterConfig.ClientAddress reads
// it, and refuses an address over it before the Host check. Each public
// route is logged once at mount, so the log lists them.
func (router *Router) Public(pattern string, handler http.Handler, options ...PublicOptions) {
	method, path := checkRoute("Public", pattern, handler)
	option := oneOption("Public", pattern, "PublicOptions", options)
	write := slices.Contains(writeMethods, method)
	switch {
	case option.Origin != originPolicyUnset && !option.Origin.valid():
		panic(fmt.Sprintf("identity: router.Public(%q): Origin is identity.SameOrigin or identity.AnyOrigin", pattern))
	case write && option.Origin == originPolicyUnset:
		panic(fmt.Sprintf("identity: router.Public(%q): a write names its Origin, identity.SameOrigin or identity.AnyOrigin", pattern))
	case !write && option.Origin != originPolicyUnset:
		panic(fmt.Sprintf("identity: router.Public(%q): Origin is for writes; a GET needs none, so remove it", pattern))
	case option.Origin == SameOrigin && option.CrossOrigin:
		panic(fmt.Sprintf("identity: router.Public(%q): a SameOrigin write refuses every other origin, so CrossOrigin would do nothing; use identity.AnyOrigin or remove CrossOrigin", pattern))
	}
	subtree := strings.HasSuffix(path, "/") || strings.HasSuffix(path, "...}")
	if option.Probe && subtree {
		panic(fmt.Sprintf("identity: router.Public(%q): a probe serves one path, never a subtree; name the path, such as \"GET /api/health\"", pattern))
	}
	if len(option.CrossOriginRequestHeaders) != 0 && !option.CrossOrigin {
		panic(fmt.Sprintf("identity: router.Public(%q): CrossOriginRequestHeaders needs CrossOrigin: true, since only a cross-origin route answers preflights", pattern))
	}
	requestHeaders := make([]string, 0, len(option.CrossOriginRequestHeaders))
	for _, name := range option.CrossOriginRequestHeaders {
		if !httpname.ValidHeaderName(name) {
			panic(fmt.Sprintf("identity: router.Public(%q): CrossOriginRequestHeaders has %q, which is not a header name", pattern, name))
		}
		name = textproto.CanonicalMIMEHeaderKey(name)
		if slices.Contains(credentialHeaders, name) {
			panic(fmt.Sprintf("identity: router.Public(%q): CrossOriginRequestHeaders has %s, but a public route takes no credentials", pattern, name))
		}
		requestHeaders = append(requestHeaders, name)
	}
	option.CrossOriginRequestHeaders = requestHeaders
	checkRateLimit("Public", pattern, option.RateLimit)
	slog.Info("AppKit public route", "pattern", pattern, "subtree", subtree, "probe", option.Probe, "origin", option.Origin.label(), "cross_origin", option.CrossOrigin, "cross_origin_request_headers", requestHeaders, "rate_limit", option.RateLimit.label())
	served := servePublic(handler, option)
	if !option.Probe {
		served = router.sessions.boundary(served)
	}
	// Inside allowAnyOrigin, so a cross-origin page can read the 429 too.
	served = router.rateLimited(option.RateLimit, router.clientAddress, served)
	// Outside the rate limit, so a cross-site request spends no token.
	if option.Origin == SameOrigin {
		served = router.sessions.requireSameOrigin(served)
	}
	if option.CrossOrigin {
		served = allowAnyOrigin(served)
	}
	router.mux.Handle(pattern, publicRoute{options: option, Handler: served})
}

// publicRoute is a public route's handler as mounted, carrying its options,
// so the preflight interceptor finds a route's options in the route table.
type publicRoute struct {
	options PublicOptions
	http.Handler
}

// credentialHeaders are the request headers that carry a credential, which a
// public route never allows across origins.
var credentialHeaders = []string{"Authorization", "Cookie", "Proxy-Authorization"}

// requireSameOrigin serves a request only from the app's own pages, with the
// check private mutations get, and answers any other 403.
func (s *Sessions) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.sameOrigin(request) {
			writeError(writer, http.StatusForbidden, "Same-origin request required.")
			return
		}
		next.ServeHTTP(writer, request)
	})
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
		handler.ServeHTTP(publicResponseWriter{writer: writer}, public)
	})
}

// allowAnyOrigin lets a page on any origin read every answer of a
// cross-origin public route, its 400, 403, 413, 421, and 429 refusals
// included, and the Retry-After header of a 429.
func allowAnyOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Expose-Headers", "Retry-After")
		next.ServeHTTP(writer, request)
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
// set. It returns the method and path.
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
	// Go unescapes a pattern's segments, so "/%61uth/" is /auth/ too.
	if unescaped, err := url.PathUnescape(path); err == nil && (unescaped == "/auth" || strings.HasPrefix(unescaped, "/auth/")) {
		panic(fmt.Sprintf("identity: router.%s(%q): /auth/ belongs to AppKit; mount the route elsewhere", kind, pattern))
	}
	if handler == nil {
		panic(fmt.Sprintf("identity: router.%s(%q): the handler is nil; pass the route's handler", kind, pattern))
	}
	return method, path
}

// oneOption returns a mount's options value, or the zero value when none is
// passed, and panics when more than one is.
func oneOption[Options any](kind, pattern, typeName string, options []Options) Options {
	if len(options) > 1 {
		panic(fmt.Sprintf("identity: router.%s(%q): pass at most one %s", kind, pattern, typeName))
	}
	var option Options
	if len(options) == 1 {
		option = options[0]
	}
	return option
}

// checkPermission panics when a guarded route names no permission.
func checkPermission(kind, pattern, permission string) {
	if permission == "" {
		panic(fmt.Sprintf("identity: router.%s(%q): a permission is required", kind, pattern))
	}
}
