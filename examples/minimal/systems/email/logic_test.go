package email

import (
	"strings"
	"testing"
	"time"
)

// These tests call the system's logic functions with fabricated values and open no database.

func TestValidAPIKey(t *testing.T) {
	for _, refused := range []string{"", "short", "1234567", "re_live 1234abcd", "re_live\t1234abcd", strings.Repeat("k", 501)} {
		if _, err := validAPIKey(refused); err != ErrInvalid {
			t.Fatalf("validAPIKey(%q) error = %v, want ErrInvalid", refused, err)
		}
	}
	for _, accepted := range []string{"12345678", strings.Repeat("k", 500)} {
		if apiKey, err := validAPIKey(accepted); err != nil || apiKey != accepted {
			t.Fatalf("validAPIKey of %d characters = %q, %v", len(accepted), apiKey, err)
		}
	}
	if apiKey, err := validAPIKey("  re_live_1234abcd\n"); err != nil || apiKey != "re_live_1234abcd" {
		t.Fatalf("validAPIKey trims to %q, %v", apiKey, err)
	}
}

func TestNewKeyRecordUsesTheGivenTimeToTheSecond(t *testing.T) {
	now := time.Date(2026, time.March, 4, 10, 30, 15, 987654321, time.FixedZone("CET", 3600))
	record := newKeyRecord(Actor{Subject: "admin"}, "re_live_1234ábcd", now)
	want := keyRecord{APIKey: "re_live_1234ábcd", LastFour: "ábcd", UpdatedBy: "admin", UpdatedAt: time.Date(2026, time.March, 4, 9, 30, 15, 0, time.UTC)}
	if record != want {
		t.Fatalf("newKeyRecord = %+v, want %+v", record, want)
	}
}
