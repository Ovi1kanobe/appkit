package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteError(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{"invalid", Invalid("A note needs text."), 400, `{"error":"A note needs text."}`},
		{"forbidden", Forbidden("Only the author may delete this note."), 403, `{"error":"Only the author may delete this note."}`},
		{"not found", NotFound("That note no longer exists."), 404, `{"error":"That note no longer exists."}`},
		{"conflict", Conflict("That tool is on loan."), 409, `{"error":"That tool is on loan."}`},
		{"unavailable", fmt.Errorf("price: %w (timeout)", Unavailable("No price right now. Try again in a moment.")), 503, `{"error":"No price right now. Try again in a moment."}`},
		{"wrapped", fmt.Errorf("deleting note 7: %w", NotFound("That note no longer exists.")), 404, `{"error":"That note no longer exists."}`},
		{"too large", &http.MaxBytesError{Limit: 8}, 413, `{"error":"The request is too large."}`},
		{"unexpected", errors.New("database is locked"), 500, `{"error":"Something went wrong."}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			WriteError(recorder, httptest.NewRequest(http.MethodGet, "/api/notes", nil), test.err)
			if recorder.Code != test.status || strings.TrimSpace(recorder.Body.String()) != test.body || recorder.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("%d %q %q", recorder.Code, recorder.Body.String(), recorder.Header().Get("Content-Type"))
			}
		})
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	first, second := NotFound("Gone."), NotFound("Gone.")
	if errors.Is(first, second) || !errors.Is(fmt.Errorf("wrapped: %w", first), first) {
		t.Fatal("errors.Is should match an error only with itself")
	}
}

func TestWriteJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	WriteJSON(recorder, http.StatusCreated, map[string]int{"id": 7})
	if recorder.Code != 201 || strings.TrimSpace(recorder.Body.String()) != `{"id":7}` || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q", recorder.Code, recorder.Body.String())
	}
}

func TestReadJSON(t *testing.T) {
	const json = "application/json"
	for _, test := range []struct {
		name        string
		contentType string
		body        string
		limit       int64
		err         error
	}{
		{"valid", json, `{"text":"hello"}`, 64, nil},
		{"valid with a charset", "Application/JSON; charset=utf-8", `{"text":"hello"}`, 64, nil},
		{"valid with whitespace", json, ` {"text":"hello"} ` + "\n", 64, nil},
		{"no content type", "", `{"text":"hello"}`, 64, ErrNotJSONContentType},
		{"form content type", "application/x-www-form-urlencoded", `{"text":"hello"}`, 64, ErrNotJSONContentType},
		{"plain text content type", "text/plain", `{"text":"hello"}`, 64, ErrNotJSONContentType},
		{"json suffix is not json", "application/merge-patch+json", `{"text":"hello"}`, 64, ErrNotJSONContentType},
		{"malformed content type", "application/json; charset", `{"text":"hello"}`, 64, ErrNotJSONContentType},
		{"empty", json, ``, 64, ErrNotJSON},
		{"not json", json, `{"text":`, 64, ErrNotJSON},
		{"wrong type", json, `{"text":7}`, 64, ErrNotJSON},
		{"second value", json, `{"text":"hello"} {"text":"evil"}`, 64, ErrNotJSON},
		{"trailing junk", json, `{"text":"hello"} junk`, 64, ErrNotJSON},
		{"too large", json, `{"text":"` + strings.Repeat("x", 100) + `"}`, 16, &http.MaxBytesError{}},
		{"value ends before the limit is hit", json, `{"text":"hello"}` + strings.Repeat(" ", 100), 32, &http.MaxBytesError{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var input struct {
				Text string `json:"text"`
			}
			request := httptest.NewRequest(http.MethodPost, "/api/notes", strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			request.Body = http.MaxBytesReader(httptest.NewRecorder(), request.Body, test.limit)
			err := ReadJSON(request, &input)
			var tooLarge *http.MaxBytesError
			switch {
			case test.err == nil && (err != nil || input.Text != "hello"):
				t.Fatalf("err=%v input=%+v", err, input)
			case test.err == ErrNotJSON || test.err == ErrNotJSONContentType:
				if !errors.Is(err, test.err) {
					t.Fatalf("err=%v, want %v", err, test.err)
				}
			case test.err != nil && !errors.As(err, &tooLarge):
				t.Fatalf("err=%v, want MaxBytesError", err)
			}
		})
	}
	// A request that does not say its body is JSON is answered 415.
	recorder := httptest.NewRecorder()
	WriteError(recorder, httptest.NewRequest(http.MethodPost, "/api/notes", nil), ErrNotJSONContentType)
	if recorder.Code != http.StatusUnsupportedMediaType || strings.TrimSpace(recorder.Body.String()) != `{"error":"Send JSON with Content-Type: application/json."}` {
		t.Fatalf("%d %q", recorder.Code, recorder.Body.String())
	}
}
