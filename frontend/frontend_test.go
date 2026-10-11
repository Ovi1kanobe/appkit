package frontend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestFrontend(t *testing.T) {
	files := fstest.MapFS{"index.html": {Data: []byte("<h1>App</h1>")}, "assets/app.js": {Data: []byte("console.log('app')")}, "assets/extensionless": {Data: []byte("asset")}}
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
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/bots/123", nil))
	if response.Code != 405 {
		t.Fatal("POST served SPA")
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
