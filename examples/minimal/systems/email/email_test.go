package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"

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
