package access

import (
	"time"

	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/identity"
)

// EmailWrite lets a person see and set the email provider key status.
const EmailWrite = "email.write"

// EmailKey lists what a person with EmailWrite receives of the key status.
type EmailKey struct {
	Set       bool      `json:"set"`
	LastFour  string    `json:"last_four,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// ViewEmailKey returns what viewer sees of the key status: all of it, since
// only people with EmailWrite reach it.
func ViewEmailKey(viewer identity.Identity, status email.KeyStatus) (EmailKey, bool) {
	return EmailKey{Set: status.Set, LastFour: status.LastFour, UpdatedAt: status.UpdatedAt}, true
}
