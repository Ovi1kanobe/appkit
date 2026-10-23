package frontend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestFrontend(t *testing.T) {
	files := fstest.MapFS{"index.html": {Data: []byte("<h1>App</h1>")}, "assets/app.js": {Data: []byte("console.log('app')")}, "assets/extensionless": {Data: []byte("asset")}, "manifest.webmanifest": {Data: []byte("{}")}}
	handler, err := New(files)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("healthy")) })
	for _, test := range []struct {
		path   string
		status int
		body   string
	}{{"/", 200, "<h1>App</h1>"}, {"/assets/app.js", 200, "console.log"}, {"/bots/123", 200, "<h1>App</h1>"}, {"/bots/", 200, "<h1>App</h1>"}, {"/assets/missing.js", 404, ""}, {"/missing.ico", 404, ""}, {"/assets/missing", 404, ""}, {"/api/health", 200, "healthy"}, {"/api/missing", 404, ""}, {"/ws/missing", 404, ""}, {"/auth/missing", 404, ""}, {"/__system-map", 404, ""}} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest("GET", test.path, nil))
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.body) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	for _, target := range []string{"/../index.html", "/%2e%2e/index.html", "/assets/../../index.html", "/assets%5c..%5cindex.html", "/%00index.html"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", target, nil))
		if response.Code != 404 {
			t.Fatalf("unsafe path %s returned %d", target, response.Code)
		}
	}
	for _, test := range []struct {
		path         string
		status       int
		cacheControl string
	}{{"/", 200, "no-cache"}, {"/index.html", 200, "no-cache"}, {"/bots/123", 200, "no-cache"}, {"/manifest.webmanifest", 200, "no-cache"}, {"/assets/app.js", 200, "public, max-age=31536000, immutable"}, {"/assets/missing.js", 404, ""}} {
		t.Run("cache "+test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", test.path, nil))
			cacheControl := response.Header().Get("Cache-Control")
			if response.Code != test.status || strings.Contains(cacheControl, "immutable") && test.status != 200 || test.cacheControl != "" && cacheControl != test.cacheControl {
				t.Fatalf("status=%d cache-control=%q", response.Code, cacheControl)
			}
		})
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/bots/123", nil))
	if response.Code != 405 {
		t.Fatal("POST served SPA")
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/manifest.webmanifest", nil))
	if response.Code != 200 || response.Header().Get("Content-Type") != "application/manifest+json" {
		t.Fatalf("manifest status=%d type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("HEAD", "/bots/123", nil))
	if response.Code != 200 || response.Body.Len() != 0 {
		t.Fatal("HEAD returned body")
	}
}

func TestMissingIndex(t *testing.T) {
	if _, err := New(fstest.MapFS{}); err == nil {
		t.Fatal("missing index accepted")
	}
}
