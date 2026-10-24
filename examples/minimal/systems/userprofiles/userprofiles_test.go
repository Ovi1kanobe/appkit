package userprofiles

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Ovi1kanobe/appkit/schema"
)

func TestRecordAndLookup(t *testing.T) {
	ctx := context.Background()
	database, err := schema.Open(ctx, filepath.Join(t.TempDir(), "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	system, err := Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if err := system.Record(ctx, "", "nobody@example.test"); err != ErrInvalid {
		t.Fatalf("empty subject: %v", err)
	}
	for _, email := range []string{"old@example.test", "new@example.test"} {
		if err := system.Record(ctx, "sam", email); err != nil {
			t.Fatal(err)
		}
	}
	profiles, err := system.Lookup(ctx, []string{"sam", "sam", "stranger"})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles["sam"].Email != "new@example.test" {
		t.Fatalf("lookup: %+v", profiles)
	}
}

// This test calls the logic function with fabricated values and opens no database.

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
