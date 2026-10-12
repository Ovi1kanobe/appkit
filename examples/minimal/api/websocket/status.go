// Package websocket adapts system outputs to authenticated WebSockets.
package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/realtime"
)

const StatusPattern = "GET /ws/status"
const StatusTopic = "status.updated"

// Status sends the page the viewer's snapshot when it opens, then the one
// PublishStatus sends every five seconds. Mount it behind access.DiagnosticsRead.
func Status(system *diagnostics.System, hub *realtime.Hub) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := hub.Accept(writer, request)
		if err != nil {
			return
		}
		defer connection.Close()
		if err := connection.Subscribe(StatusTopic); err != nil {
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

// PublishStatus sends each subscriber their view of the diagnostics snapshot
// every five seconds until ctx ends.
func PublishStatus(ctx context.Context, hub *realtime.Hub, system *diagnostics.System) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshot := system.Snapshot()
			publishEach(ctx, hub, StatusTopic, func(person identity.Identity) ([]byte, bool) {
				view, ok := access.ViewStatus(person, snapshot)
				return marshal(view, ok)
			})
		}
	}
}

// publishEach sends each subscriber of topic what view returns for them.
func publishEach(ctx context.Context, hub *realtime.Hub, topic string, view realtime.View) {
	_ = hub.PublishEach(ctx, topic, view)
}

// marshal encodes value for a subscriber who may see it.
func marshal(value any, ok bool) ([]byte, bool) {
	if !ok {
		return nil, false
	}
	data, err := json.Marshal(value)
	return data, err == nil
}
