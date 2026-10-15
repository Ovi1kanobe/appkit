// Package api reads and answers HTTP requests: JSON bodies within a limit, and
// errors with the status a system's error carries. A system declares each error a person can be shown with
// Invalid, Forbidden, NotFound, Conflict, or Unavailable, whose text is the
// sentence the person reads. WriteError sends that sentence with the matching
// status, and any other error as a logged 500 with a generic message, so no
// internal detail reaches a browser.
package api

import (
	"encoding/json"
	"errors"
	"io"
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

// Unavailable is an error for a service the system depends on that did not
// answer, so the person should try again later, answered with 503.
func Unavailable(text string) error {
	return &statusError{status: http.StatusServiceUnavailable, text: text}
}

// ErrNotJSON is the answer when a request body cannot be decoded.
var ErrNotJSON = Invalid("The request body is not valid JSON.")

// ReadJSON decodes the request body into value: one JSON value and nothing
// after it. A body over its limit returns the *http.MaxBytesError, which
// WriteError answers with 413; anything else that fails returns ErrNotJSON.
func ReadJSON(request *http.Request, value any) error {
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(value); err != nil {
		return notJSON(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return ErrNotJSON
		}
		return notJSON(err)
	}
	return nil
}

// notJSON keeps a too-large error, which carries its own status, and turns
// every other decoding failure into ErrNotJSON.
func notJSON(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return err
	}
	return ErrNotJSON
}

// WriteJSON answers with status and value encoded as JSON.
func WriteJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// WriteError answers with {"error": text}. An error made by Invalid,
// Forbidden, NotFound, Conflict, or Unavailable, even when wrapped, is sent
// with its own text and status; an Unavailable one is also logged as a
// warning with everything it wraps, which says what did not answer. A body
// over its limit is 413. Any other error is logged with the request and
// answered with 500 and a generic message.
func WriteError(writer http.ResponseWriter, request *http.Request, err error) {
	var known *statusError
	if errors.As(err, &known) {
		if known.status == http.StatusServiceUnavailable {
			slog.WarnContext(request.Context(), "request unavailable", "method", request.Method, "path", request.URL.Path, "error", err)
		}
		WriteJSON(writer, known.status, map[string]string{"error": known.text})
		return
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteJSON(writer, http.StatusRequestEntityTooLarge, map[string]string{"error": "The request is too large."})
		return
	}
	slog.ErrorContext(request.Context(), "request failed", "method", request.Method, "path", request.URL.Path, "error", err)
	WriteJSON(writer, http.StatusInternalServerError, map[string]string{"error": "Something went wrong."})
}
