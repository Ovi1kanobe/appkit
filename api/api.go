// Package api answers HTTP requests with JSON, and with the status a system's
// error carries. A system declares each error a person can be shown with
// Invalid, Forbidden, NotFound, or Conflict, whose text is the sentence the
// person reads. WriteError sends that sentence with the matching status, and
// any other error as a logged 500 with a generic message, so no internal
// detail reaches a browser.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// statusError is an error a person may be shown, with the status it means.
// Each constructor returns a distinct pointer, so errors.Is tells two errors
// with the same text apart.
type statusError struct {
	status int
	text   string
}

func (err *statusError) Error() string { return err.text }

// Invalid is an error for input the system refuses, answered with 400.
func Invalid(text string) error { return &statusError{status: http.StatusBadRequest, text: text} }

// Forbidden is an error for an action the person may not take, answered with 403.
func Forbidden(text string) error { return &statusError{status: http.StatusForbidden, text: text} }

// NotFound is an error for a record that does not exist, answered with 404.
func NotFound(text string) error { return &statusError{status: http.StatusNotFound, text: text} }

// Conflict is an error for a change the current state refuses, answered with 409.
func Conflict(text string) error { return &statusError{status: http.StatusConflict, text: text} }

// WriteJSON answers with status and value encoded as JSON.
func WriteJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// WriteError answers with {"error": text}. An error made by Invalid,
// Forbidden, NotFound, or Conflict, even when wrapped, is sent with its own
// text and status. Any other error is logged with the request and answered
// with 500 and a generic message.
func WriteError(writer http.ResponseWriter, request *http.Request, err error) {
	var known *statusError
	if errors.As(err, &known) {
		WriteJSON(writer, known.status, map[string]string{"error": known.text})
		return
	}
	slog.ErrorContext(request.Context(), "request failed", "method", request.Method, "path", request.URL.Path, "error", err)
	WriteJSON(writer, http.StatusInternalServerError, map[string]string{"error": "Something went wrong."})
}
