package websocket

import (
	"context"
	"net/http"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/realtime"
)

const EmailPattern = "GET /ws/email"
const EmailTopic = "email.changed"

// Email subscribes the page to email key status changes. Mount it behind access.EmailWrite.
func Email(hub *realtime.Hub) http.Handler {
	return hub.Subscriber(EmailTopic)
}

// NewEmailPublisher sends each subscriber their view of the key status after
// it changes. There is one status, so every change has the same key and only
// the latest is sent. Pass Add as the email system's onChange, and start Run
// in a goroutine.
func NewEmailPublisher(hub *realtime.Hub) *realtime.Publisher[struct{}, email.Change] {
	return realtime.NewPublisher(hub, EmailTopic,
		func(email.Change) struct{} { return struct{}{} },
		func(_ context.Context, person identity.Identity, change email.Change) ([]byte, bool) {
			view, ok := access.ViewEmailKey(person, change.Status)
			return marshal(view, ok)
		})
}
