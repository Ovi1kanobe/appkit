package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	logged := &capturedLog{}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(logged))
	defer slog.SetDefault(previousLogger)
	var changes []Change
	system, err := Open(ctx, database, key, func(change Change) { changes = append(changes, change) })
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
	if len(changes) != 1 || changes[0].By != "admin" || !changes[0].At.Equal(status.UpdatedAt) {
		t.Fatalf("changes = %+v, want one by admin at %v", changes, status.UpdatedAt)
	}
	if lines := logged.matching("INFO email key"); !slices.Equal(lines, []string{"INFO email key set subject=admin"}) {
		t.Fatalf("logged %q, want one line with the subject and nothing of the key", lines)
	}
}

// capturedLog is a slog handler that keeps each record as its level, message,
// and attributes on one line, so a test can check what a change logged.
type capturedLog struct {
	lock  sync.Mutex
	lines []string
}

func (captured *capturedLog) Enabled(context.Context, slog.Level) bool { return true }

func (captured *capturedLog) Handle(_ context.Context, record slog.Record) error {
	line := record.Level.String() + " " + record.Message
	record.Attrs(func(attribute slog.Attr) bool {
		line += " " + attribute.String()
		return true
	})
	captured.lock.Lock()
	defer captured.lock.Unlock()
	captured.lines = append(captured.lines, line)
	return nil
}

func (captured *capturedLog) WithAttrs([]slog.Attr) slog.Handler { return captured }

func (captured *capturedLog) WithGroup(string) slog.Handler { return captured }

// matching returns the captured lines that start with prefix.
func (captured *capturedLog) matching(prefix string) []string {
	captured.lock.Lock()
	defer captured.lock.Unlock()
	var matched []string
	for _, line := range captured.lines {
		if strings.HasPrefix(line, prefix) {
			matched = append(matched, line)
		}
	}
	return matched
}
