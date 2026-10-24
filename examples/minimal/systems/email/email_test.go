package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ovi1kanobe/appkit/encryption"
	"github.com/Ovi1kanobe/appkit/schema"
)

// TestAPIKeyIsStoredEncrypted checks the key never reaches the database in plain text.
func TestAPIKeyIsStoredEncrypted(t *testing.T) {
	ctx := context.Background()
	database, err := schema.Open(ctx, filepath.Join(t.TempDir(), "app.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	secret := make([]byte, 32)
	rand.Read(secret)
	key, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(secret))
	if err != nil {
		t.Fatal(err)
	}
	system, err := Open(ctx, database, key, func(Change) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := system.SetAPIKey(ctx, Actor{Subject: "admin"}, "short"); err != ErrInvalid {
		t.Fatalf("short key: %v", err)
	}
	if err := system.SetAPIKey(ctx, Actor{Subject: "admin"}, "re_live_1234abcd"); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := database.QueryRow(`SELECT api_key FROM email_settings`).Scan(&stored); err != nil || bytes.Contains(stored, []byte("re_live")) {
		t.Fatalf("stored in plain text or unreadable: %v", err)
	}
	status, err := system.KeyStatus(ctx)
	if err != nil || !status.Set || status.LastFour != "abcd" {
		t.Fatalf("status = %+v, %v", status, err)
	}
	if apiKey, err := system.apiKey(ctx); err != nil || apiKey != "re_live_1234abcd" {
		t.Fatalf("apiKey = %q, %v", apiKey, err)
	}
}

// The tests below call the logic functions with fabricated values and open no database.

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
