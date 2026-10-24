package access

import (
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
	"github.com/Ovi1kanobe/appkit/identity"
)

// DiagnosticsRead lets a person or a calling application see process status.
const DiagnosticsRead = "diagnostics.read"

// Status lists what a person or calling application with DiagnosticsRead
// receives of the process status.
type Status struct {
	UptimeSeconds int64 `json:"uptime_seconds"`
}

// ViewStatus returns what viewer sees of the process status: all of it.
func ViewStatus(viewer identity.Identity, status diagnostics.Status) (Status, bool) {
	return Status{UptimeSeconds: status.UptimeSeconds}, true
}
