// Package http translates HTTP requests into system calls and results into responses.
package http

import (
	"net/http"

	"github.com/Ovi1kanobe/appkit/api"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
)

const StatusPattern = "GET /api/status"

// Status serves a diagnostics snapshot to bearer clients. Mount it behind access.DiagnosticsRead.
func Status(system *diagnostics.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		view, _ := access.ViewStatus(viewer(request), system.Snapshot())
		api.WriteJSON(writer, http.StatusOK, view)
	})
}
