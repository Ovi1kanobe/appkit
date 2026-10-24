// Package diagnostics owns the example's small process-status capability. The
// status changes with the clock rather than with anything a person does, so
// the system's own Run reports it on a timer.
package diagnostics

import (
	"context"
	"time"
)

// reportEvery is how often Run reports the status: often enough for a page to
// count up visibly, rare enough to cost nothing.
const reportEvery = 5 * time.Second

// diagnosticsSubject is who a timed report is by: the system itself, since no
// person acts.
const diagnosticsSubject = "diagnostics"

type Status struct {
	UptimeSeconds int64
}

// Change is the status at At, reported by the system's own timer.
type Change struct {
	Status Status
	At     time.Time
	By     string
}

// System has no lock: started is set once by New and only read after, and
// onChange is called from Run alone.
type System struct {
	started  time.Time
	onChange func(Change)
}

// New starts the uptime clock. onChange runs after every timed report and
// must not block.
func New(onChange func(Change)) *System {
	return &System{started: time.Now(), onChange: onChange}
}

func (system *System) Snapshot() Status {
	return statusAt(system.started, time.Now())
}

// Run reports the status every reportEvery until ctx ends. There is nothing
// to finish at shutdown, so it returns at once.
func (system *System) Run(ctx context.Context) error {
	ticker := time.NewTicker(reportEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			system.onChange(Change{Status: statusAt(system.started, now), At: now, By: diagnosticsSubject})
		}
	}
}

// statusAt is the status at now of a process that started at started.
func statusAt(started, now time.Time) Status {
	return Status{UptimeSeconds: int64(now.Sub(started).Seconds())}
}
