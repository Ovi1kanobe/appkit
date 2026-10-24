package notes

import (
	"strings"
	"testing"
	"time"
)

// These tests call the logic functions with fabricated values and open no database.

func TestValidText(t *testing.T) {
	for _, refused := range []string{"", "   ", "\t\n", strings.Repeat("é", maximumLength+1)} {
		if _, err := validText(refused); err != ErrInvalid {
			t.Fatalf("validText(%q) error = %v, want ErrInvalid", refused, err)
		}
	}
	longest := strings.Repeat("é", maximumLength)
	if text, err := validText(longest); err != nil || text != longest {
		t.Fatalf("validText of %d characters = %q, %v", maximumLength, text, err)
	}
	if text, err := validText("  Buy milk \n"); err != nil || text != "Buy milk" {
		t.Fatalf("validText trims to %q, %v", text, err)
	}
	if text, err := validText(" " + longest + " "); err != nil || text != longest {
		t.Fatalf("validText counts surrounding space: %q, %v", text, err)
	}
}

func TestNewNoteUsesTheGivenTimeToTheSecond(t *testing.T) {
	now := time.Date(2026, time.March, 4, 10, 30, 15, 987654321, time.FixedZone("CET", 3600))
	note := newNote(Actor{Subject: "sam"}, "Buy milk", now)
	want := time.Date(2026, time.March, 4, 9, 30, 15, 0, time.UTC)
	if note.ID != 0 || note.Text != "Buy milk" || note.CreatedBy != "sam" || !note.CreatedAt.Equal(want) || note.CreatedAt.Location() != time.UTC {
		t.Fatalf("newNote = %+v, want created at %v", note, want)
	}
}
