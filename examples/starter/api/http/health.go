package http

import (
	"net/http"

	"github.com/Ovi1kanobe/appkit/api"
)

const HealthPattern = "GET /api/health"

// Health reports that the process is serving requests. It needs no sign-in.
func Health() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		api.WriteJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
}
