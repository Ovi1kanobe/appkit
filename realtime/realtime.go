// Package realtime provides authenticated WebSocket mechanics, not domain events.
package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/coder/websocket"
)

var ErrClosed = errors.New("realtime: connection closed")
var errUnauthenticated = errors.New("realtime: unauthenticated")

// AuthenticationEnded is the WebSocket close code sent when the request's
// authentication ends (sign-out, revocation, or expiry), so a browser can tell
// it apart from a network drop.
const AuthenticationEnded = 4401

// Hub tracks local connections and subscriptions. Its zero value is ready to use.
// Applications own lifetime, topic authorization, and event scheduling/coalescing.
type Hub struct {
	mu          sync.Mutex
	connections map[*Conn]map[string]struct{}
	closed      bool
}

type Conn struct {
	socket      *websocket.Conn
	hub         *Hub
	actor       identity.Identity
	closed      sync.Once
	stopContext func() bool
}

// Accept requires an identity already authenticated by the application. The
// underlying library enforces same-origin requests and permits non-browser clients.
// The caller must defer Close and continuously Read to handle ping/pong and cleanup.
func (hub *Hub) Accept(writer http.ResponseWriter, request *http.Request) (*Conn, error) {
	actor, ok := identity.FromContext(request.Context())
	if !ok {
		writeError(writer, http.StatusUnauthorized, "Sign in required.")
		return nil, errUnauthenticated
	}
	hub.mu.Lock()
	closed := hub.closed
	hub.mu.Unlock()
	if closed {
		writeError(writer, http.StatusServiceUnavailable, "Shutting down")
		return nil, ErrClosed
	}
	socket, err := websocket.Accept(writer, request, nil)
	if err != nil {
		return nil, err
	}
	socket.SetReadLimit(64 * 1024)
	connection := &Conn{socket: socket, hub: hub, actor: actor}
	hub.mu.Lock()
	if hub.closed {
		hub.mu.Unlock()
		_ = socket.CloseNow()
		return nil, ErrClosed
	}
	if hub.connections == nil {
		hub.connections = make(map[*Conn]map[string]struct{})
	}
	hub.connections[connection] = make(map[string]struct{})
	connection.stopContext = context.AfterFunc(request.Context(), func() { connection.release(true) })
	hub.mu.Unlock()
	return connection, nil
}

func (connection *Conn) Identity() identity.Identity {
	actor := connection.actor
	actor.Groups = append([]string(nil), actor.Groups...)
	actor.Roles = append([]string(nil), actor.Roles...)
	return actor
}

// Read accepts text frames only. Exactly one goroutine may call Read at a time.
func (connection *Conn) Read(ctx context.Context) ([]byte, error) {
	kind, data, err := connection.socket.Read(ctx)
	if err != nil {
		connection.Close()
		return nil, err
	}
	if kind != websocket.MessageText {
		connection.Close()
		return nil, errors.New("realtime: text frames required")
	}
	return data, nil
}

// Write is safe for concurrent callers. Each write is bounded to five seconds
// (or the caller's earlier deadline); failed/slow connections are removed.
func (connection *Conn) Write(ctx context.Context, data []byte) error {
	writeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := connection.socket.Write(writeContext, websocket.MessageText, data)
	if err != nil {
		connection.Close()
	}
	return err
}

// Ping requires a concurrent Read loop to receive the pong.
func (connection *Conn) Ping(ctx context.Context) error {
	pingContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := connection.socket.Ping(pingContext)
	if err != nil {
		connection.Close()
	}
	return err
}

// Subscribe records a transport topic. Authorize the topic in application code first.
func (connection *Conn) Subscribe(topic string) error {
	if topic == "" {
		return errors.New("realtime: empty topic")
	}
	connection.hub.mu.Lock()
	defer connection.hub.mu.Unlock()
	topics, exists := connection.hub.connections[connection]
	if !exists {
		return ErrClosed
	}
	topics[topic] = struct{}{}
	return nil
}

func (connection *Conn) Unsubscribe(topic string) {
	connection.hub.mu.Lock()
	defer connection.hub.mu.Unlock()
	delete(connection.hub.connections[connection], topic)
}

// Close immediately releases the socket and all subscriptions. It is idempotent.
func (connection *Conn) Close() { connection.release(false) }

func (connection *Conn) release(authenticationEnded bool) {
	connection.closed.Do(func() {
		connection.hub.mu.Lock()
		delete(connection.hub.connections, connection)
		if connection.stopContext != nil {
			connection.stopContext()
		}
		connection.hub.mu.Unlock()
		if authenticationEnded {
			// Subscriptions are already gone; the close handshake is bounded by the library.
			_ = connection.socket.Close(AuthenticationEnded, "authentication ended")
			return
		}
		_ = connection.socket.CloseNow()
	})
}

// Publish sends the same data to every subscriber of topic.
func (hub *Hub) Publish(ctx context.Context, topic string, data []byte) error {
	return hub.PublishEach(ctx, topic, func(identity.Identity) ([]byte, bool) { return data, true })
}

// PublishEach asks view, once per subscriber of topic, what that person
// receives, and sends it; view returns false to send that person nothing.
// It writes sequentially to a snapshot of subscribers with no hidden queues or
// workers; supply a deadline for the total fanout budget. A concurrent
// unsubscribe or close may race with the captured snapshot.
func (hub *Hub) PublishEach(ctx context.Context, topic string, view func(identity.Identity) ([]byte, bool)) error {
	hub.mu.Lock()
	connections := make([]*Conn, 0)
	for connection, topics := range hub.connections {
		if _, subscribed := topics[topic]; subscribed {
			connections = append(connections, connection)
		}
	}
	hub.mu.Unlock()
	var failures []error
	for _, connection := range connections {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		data, send := view(connection.Identity())
		if !send {
			continue
		}
		if err := connection.Write(ctx, data); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// DisconnectSubject affects current connections only. Applications must separately
// invalidate local sessions or revoke credentials to prevent reconnection.
func (hub *Hub) DisconnectSubject(subject string) {
	hub.mu.Lock()
	var connections []*Conn
	for connection := range hub.connections {
		if connection.actor.Subject == subject {
			connections = append(connections, connection)
		}
	}
	hub.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
}

// Close stops accepting and releases all current connections. The application calls it.
func (hub *Hub) Close() {
	hub.mu.Lock()
	hub.closed = true
	var connections []*Conn
	for connection := range hub.connections {
		connections = append(connections, connection)
	}
	hub.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
}

// writeError answers WebSocket requests that cannot be upgraded with {"error": message}, the
// shape applications use, so pages read every error the same way.
func writeError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": message})
}
