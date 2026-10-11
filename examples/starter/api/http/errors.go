package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

// writeError translates system errors into status codes and {"error"} bodies.
// Unexpected errors are logged and answered with a generic message.
// Each system's sentinel errors are added to the switch as the system is added.
func writeError(writer http.ResponseWriter, request *http.Request, err error) {
	status := http.StatusInternalServerError
	switch {
	}
	message := err.Error()
	if status == http.StatusInternalServerError {
		slog.ErrorContext(request.Context(), "request failed", "method", request.Method, "path", request.URL.Path, "error", err)
		message = "Something went wrong."
	}
	writeJSON(writer, status, map[string]string{"error": message})
}
