package diagnostics

import (
	"testing"
	"time"
)

// This test calls the logic function with fabricated values.

func TestStatusAtCountsWholeSeconds(t *testing.T) {
	started := time.Date(2026, time.March, 4, 10, 0, 0, 0, time.UTC)
	now := started.Add(90*time.Minute + 999*time.Millisecond)
	if status := statusAt(started, now); status.UptimeSeconds != 5400 {
		t.Fatalf("statusAt = %+v, want 5400 seconds", status)
	}
}
