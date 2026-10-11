package websocket

import (
	"context"
	"net/http"
	"sync"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/realtime"
)

const EmailPattern = "GET /ws/email"
const EmailTopic = "email.changed"

// Email subscribes the page to email key status changes. Mount it behind access.EmailWrite.
func Email(hub *realtime.Hub) http.Handler {
	return subscribe(hub, EmailTopic)
}

// EmailPublisher sends each subscriber their view of the key status after it
// changes. Pass Add as the email system's onChange, and start Run in a goroutine.
type EmailPublisher struct {
	hub    *realtime.Hub
	mutex  sync.Mutex
	latest *email.Change
	signal chan struct{}
}

func NewEmailPublisher(hub *realtime.Hub) *EmailPublisher {
	return &EmailPublisher{hub: hub, signal: make(chan struct{}, 1)}
}

// Add never blocks a request. It keeps only the latest status until Run sends it.
func (publisher *EmailPublisher) Add(change email.Change) {
	publisher.mutex.Lock()
	publisher.latest = &change
	publisher.mutex.Unlock()
	select {
	case publisher.signal <- struct{}{}:
	default:
	}
}

// Run publishes the latest status until ctx ends.
func (publisher *EmailPublisher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-publisher.signal:
			publisher.mutex.Lock()
			change := publisher.latest
			publisher.mutex.Unlock()
			if change == nil {
				continue
			}
			publishEach(ctx, publisher.hub, EmailTopic, func(person identity.Identity) ([]byte, bool) {
				view, ok := access.ViewEmailKey(person, change.Status)
				return marshal(view, ok)
			})
		}
	}
}
