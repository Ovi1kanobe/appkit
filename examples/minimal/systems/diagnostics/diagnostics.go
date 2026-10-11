// Package diagnostics owns the example's small process-status capability.
package diagnostics

import "time"

type System struct{ started time.Time }
type Status struct {
	UptimeSeconds int64 `json:"uptime_seconds"`
}

func New() *System { return &System{started: time.Now()} }
func (system *System) Snapshot() Status {
	return Status{UptimeSeconds: int64(time.Since(system.started).Seconds())}
}
