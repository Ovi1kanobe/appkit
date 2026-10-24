// Package diagnostics owns the example's small process-status capability.
package diagnostics

import "time"

type System struct{ started time.Time }
type Status struct {
	UptimeSeconds int64 `json:"uptime_seconds"`
}

func New() *System { return &System{started: time.Now()} }
func (system *System) Snapshot() Status {
	return statusAt(system.started, time.Now())
}

// statusAt is the status at now of a process that started at started.
func statusAt(started, now time.Time) Status {
	return Status{UptimeSeconds: int64(now.Sub(started).Seconds())}
}
