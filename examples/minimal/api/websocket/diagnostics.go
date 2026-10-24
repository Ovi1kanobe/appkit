// Package websocket adapts system outputs to authenticated WebSockets.
package websocket

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/realtime"
)

const StatusPattern = "GET /ws/status"
const DiagnosticsTopic = "diagnostics.changed"

// Status subscribes the page to status changes and sends it the viewer's
// snapshot first, right after Ready, because no HTTP route serves the status
// to a page and the next timed report may be a while away. A report already
// being sent can arrive after the snapshot and be older than it; the next
// report replaces it, which is safe here and would not be for a value that
// changes rarely. Mount it behind access.DiagnosticsRead.
func Status(system *diagnostics.System, hub *realtime.Hub) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := hub.Accept(writer, request)
		if err != nil {
			return
		}
		defer connection.Close()
		if err := connection.Subscribe(DiagnosticsTopic); err != nil {
			return
		}
		if connection.Write(request.Context(), []byte(realtime.Ready)) != nil {
			return
		}
		if data, ok := marshal(access.ViewStatus(connection.Identity(), system.Snapshot())); ok {
			if connection.Write(request.Context(), data) != nil {
				return
			}
		}
		connection.Keep(request.Context())
	})
}

// NewDiagnosticsPublisher sends each subscriber their view of the status after
// every timed report. There is one status, so every change has the same key
// and only the latest is sent. Pass Add as the diagnostics system's onChange,
// and start Run in a goroutine.
func NewDiagnosticsPublisher(hub *realtime.Hub) *realtime.Publisher[struct{}, diagnostics.Change] {
	return realtime.NewPublisher(hub, DiagnosticsTopic,
		func(diagnostics.Change) struct{} { return struct{}{} },
		func(_ context.Context, change diagnostics.Change) (realtime.View, error) {
			return func(person identity.Identity) ([]byte, bool) {
				view, ok := access.ViewStatus(person, change.Status)
				return marshal(view, ok)
			}, nil
		})
}

// marshal encodes value for a subscriber who may see it.
func marshal(value any, ok bool) ([]byte, bool) {
	if !ok {
		return nil, false
	}
	data, err := json.Marshal(value)
	return data, err == nil
}
