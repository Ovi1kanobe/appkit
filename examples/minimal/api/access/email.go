package access

import (
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/identity"
)

// EmailWrite lets a person see and set the email provider key status.
const EmailWrite = "email.write"

// ViewEmailKey returns what viewer sees of the key status: all of it, since
// only people with EmailWrite reach it.
func ViewEmailKey(viewer identity.Identity, status email.KeyStatus) (email.KeyStatus, bool) {
	return status, true
}
