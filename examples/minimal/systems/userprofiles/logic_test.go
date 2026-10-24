package userprofiles

import "testing"

// These tests call the system's logic functions with fabricated values and open no database.

func TestValidSubject(t *testing.T) {
	for _, refused := range []string{"", "   ", "\t\n"} {
		if err := validSubject(refused); err != ErrInvalid {
			t.Fatalf("validSubject(%q) error = %v, want ErrInvalid", refused, err)
		}
	}
	if err := validSubject("sam"); err != nil {
		t.Fatalf("validSubject(\"sam\") error = %v", err)
	}
}
