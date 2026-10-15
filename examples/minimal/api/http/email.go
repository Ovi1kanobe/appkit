package http

import (
	"net/http"

	"github.com/Ovi1kanobe/appkit/api"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
)

const (
	EmailKeyStatusPattern = "GET /api/email/key"
	SetEmailKeyPattern    = "PUT /api/email/key"
)

// EmailKeyStatus reports whether the provider API key is set, never the key.
// Mount it behind access.EmailWrite.
func EmailKeyStatus(system *email.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, err := system.KeyStatus(request.Context())
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		view, _ := access.ViewEmailKey(viewer(request), status)
		api.WriteJSON(writer, http.StatusOK, view)
	})
}

// SetEmailKey replaces the provider API key from {"api_key"}. Mount it behind access.EmailWrite.
func SetEmailKey(system *email.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			APIKey string `json:"api_key"`
		}
		if err := api.ReadJSON(request, &input); err != nil {
			api.WriteError(writer, request, err)
			return
		}
		if err := system.SetAPIKey(request.Context(), email.Actor{Subject: viewer(request).Subject}, input.APIKey); err != nil {
			api.WriteError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}
