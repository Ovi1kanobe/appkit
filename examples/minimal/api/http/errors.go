package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
)

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// writeError translates system errors into status codes and {"error"} bodies.
// Unexpected errors are logged and answered with a generic message.
func writeError(writer http.ResponseWriter, request *http.Request, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, notes.ErrInvalid), errors.Is(err, email.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, access.ErrNotAuthor):
		status = http.StatusForbidden
	case errors.Is(err, notes.ErrNotFound):
		status = http.StatusNotFound
	}
	message := err.Error()
	if status == http.StatusInternalServerError {
		slog.ErrorContext(request.Context(), "request failed", "method", request.Method, "path", request.URL.Path, "error", err)
		message = "Something went wrong."
	}
	writeJSON(writer, status, map[string]string{"error": message})
}
