package access

import (
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
	"github.com/Ovi1kanobe/appkit/identity"
)

// DiagnosticsRead lets a person or bearer client see process status.
const DiagnosticsRead = "diagnostics.read"

// ViewStatus returns what viewer sees of the process status: all of it.
func ViewStatus(viewer identity.Identity, status diagnostics.Status) (diagnostics.Status, bool) {
	return status, true
}
