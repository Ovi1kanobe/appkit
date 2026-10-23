package identity

import (
	"fmt"
	"net/http"
	"net/textproto"
	"slices"
	"strings"
)

// preflightMethods are the methods a preflight may ask for: every route
// method, and HEAD, which a GET route answers.
var preflightMethods = append([]string{http.MethodHead}, routeMethods...)

// preflight answers a CORS preflight for the route its requested method
// resolves to, without reaching that route, reading the body, or spending a
// rate limit token. It answers 204 only for a public route with CrossOrigin
// whose Host check and Origin policy pass and whose
// CrossOriginRequestHeaders cover every requested header. It allows the
// requested headers, every method whose route at the path is public with
// CrossOrigin and whose Origin policy passes, and never a credential. A
// malformed preflight answers 400, a route that is not cross-origin 403
// without the allow header, and any other refusal 403 or 421 with it, so the
// page can read why.
func (router *Router) preflight(writer http.ResponseWriter, request *http.Request) {
	header := writer.Header()
	header.Add("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
	if origins := request.Header.Values("Origin"); len(origins) != 1 || origins[0] == "" {
		writeError(writer, http.StatusBadRequest, "A preflight names one Origin.")
		return
	}
	methods := request.Header.Values("Access-Control-Request-Method")
	if len(methods) != 1 || !slices.Contains(preflightMethods, methods[0]) {
		writeError(writer, http.StatusBadRequest, fmt.Sprintf("A preflight names one method in Access-Control-Request-Method, one of %s.", strings.Join(preflightMethods, ", ")))
		return
	}
	requestedHeaders, valid := parseRequestedHeaders(request.Header.Values("Access-Control-Request-Headers"))
	if !valid {
		writeError(writer, http.StatusBadRequest, "A preflight lists header names, separated by commas, in Access-Control-Request-Headers.")
		return
	}
	option, found := router.publicMount(request, methods[0])
	if !found || !option.CrossOrigin {
		writeError(writer, http.StatusForbidden, "This route does not accept requests from other origins.")
		return
	}
	header.Set("Access-Control-Allow-Origin", "*")
	answer := http.Handler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !router.sessions.originAllowed(option, request) {
			writeError(writer, http.StatusForbidden, "Same-origin request required.")
			return
		}
		for _, name := range requestedHeaders {
			if !slices.Contains(option.CrossOriginRequestHeaders, name) {
				writeError(writer, http.StatusForbidden, fmt.Sprintf("This route does not accept the %s header from other origins.", name))
				return
			}
		}
		var allowed []string
		for _, method := range routeMethods {
			other, found := router.publicMount(request, method)
			if !found || !other.CrossOrigin || !router.sessions.originAllowed(other, request) {
				continue
			}
			allowed = append(allowed, method)
			if method == http.MethodGet {
				allowed = append(allowed, http.MethodHead)
			}
		}
		header.Set("Access-Control-Allow-Methods", strings.Join(allowed, ", "))
		if len(requestedHeaders) != 0 {
			header.Set("Access-Control-Allow-Headers", strings.Join(requestedHeaders, ", "))
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	if !option.Probe {
		answer = router.sessions.boundary(answer)
	}
	answer.ServeHTTP(writer, request)
}

// publicMount returns the options of the public route a request with method
// would reach at request's path, and whether it reaches one.
func (router *Router) publicMount(request *http.Request, method string) (PublicOptions, bool) {
	probe := request.Clone(request.Context())
	probe.Method = method
	_, pattern := router.mux.Handler(probe)
	router.publicMountsMutex.RLock()
	defer router.publicMountsMutex.RUnlock()
	option, found := router.publicMounts[pattern]
	return option, found
}

// originAllowed reports whether a route's Origin policy lets request
// through: SameOrigin only from the app's own pages, anything else always.
func (s *Sessions) originAllowed(option PublicOptions, request *http.Request) bool {
	return option.Origin != SameOrigin || s.sameOrigin(request)
}

// parseRequestedHeaders reads Access-Control-Request-Headers, a
// comma-separated list over one or more lines, into canonical header names,
// and reports whether every entry is a header name. No header, or an empty
// one, is an empty list.
func parseRequestedHeaders(values []string) ([]string, bool) {
	joined := strings.TrimSpace(strings.Join(values, ","))
	if joined == "" {
		return nil, true
	}
	var names []string
	for entry := range strings.SplitSeq(joined, ",") {
		name := strings.Trim(entry, " \t")
		if !validHeaderName(name) {
			return nil, false
		}
		names = append(names, textproto.CanonicalMIMEHeaderKey(name))
	}
	return names, true
}

// validHeaderName reports whether name is a non-empty HTTP header name: only
// letters, digits, and the token punctuation RFC 9110 allows.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		isLetterOrDigit := character < 128 && (character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9')
		if !isLetterOrDigit && !strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			return false
		}
	}
	return true
}
