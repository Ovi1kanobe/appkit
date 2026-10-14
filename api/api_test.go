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
		{"wrapped", fmt.Errorf("deleting note 7: %w", NotFound("That note no longer exists.")), 404, `{"error":"That note no longer exists."}`},
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
