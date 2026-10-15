package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLimitBodies(t *testing.T) {
	read := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, err := io.ReadAll(request.Body); err != nil {
			WriteError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	// pass stands for any wrapper on a route line, such as sessions.Require.
	pass := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { next.ServeHTTP(writer, request) })
	}
	mux := http.NewServeMux()
	mux.Handle("PUT /api/notes", read)
	mux.Handle("GET /api/notes", read)
	mux.Handle("PUT /api/photos", LimitBody(32, read))
	mux.Handle("PUT /api/nested", pass(LimitBody(32, read)))
	mux.Handle("PUT /api/tiny", LimitBody(2, read))
	mux.Handle("PUT /api/twice", LimitBody(2, LimitBody(32, read)))
	for _, test := range []struct {
		name    string
		handler http.Handler
		method  string
		path    string
		body    string
		status  int
	}{
		{"default allows", LimitBodies(8, mux), "PUT", "/api/notes", "small", 204},
		{"default refuses", LimitBodies(8, mux), "PUT", "/api/notes", "far too large a body", 413},
		{"no body", LimitBodies(8, mux), "GET", "/api/notes", "", 204},
		{"route raises", LimitBodies(8, mux), "PUT", "/api/photos", "far too large a body", 204},
		{"route limit still holds", LimitBodies(8, mux), "PUT", "/api/photos", strings.Repeat("x", 33), 413},
		{"route limit inside a wrapper", LimitBodies(8, mux), "PUT", "/api/nested", "far too large a body", 204},
		{"route lowers", LimitBodies(8, mux), "PUT", "/api/tiny", "abc", 413},
		{"nearest the handler wins", LimitBodies(8, mux), "PUT", "/api/twice", "far too large a body", 204},
		{"route limit alone", mux, "PUT", "/api/tiny", "abc", 413},
		{"nearest wins alone too", mux, "PUT", "/api/twice", "far too large a body", 204},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body io.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			}
			recorder := httptest.NewRecorder()
			test.handler.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, body))
			if recorder.Code != test.status {
				t.Fatalf("%d %s, want %d", recorder.Code, recorder.Body.String(), test.status)
			}
		})
	}
}
