// Package email owns the connection to an external email provider. It stores
// the provider API key encrypted and never returns it; callers only learn
// whether it is set and its last four characters.
package email

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Ovi1kanobe/appkit/encryption"
	"github.com/Ovi1kanobe/appkit/schema"
)

var (
	ErrInvalid = errors.New("An API key needs between 8 and 500 characters and no spaces.")
	ErrNotSet  = errors.New("The email provider API key is not set.")
)

// apiKeyLabel binds the encrypted key to its table, column, and row.
const apiKeyLabel = "email_settings.api_key:1"

// Actor is the person changing email settings. Transport builds it from the request identity.
type Actor struct{ Subject string }

// KeyStatus describes the stored API key without revealing it.
type KeyStatus struct {
	Set       bool      `json:"set"`
	LastFour  string    `json:"last_four,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Change is the key status after it changed.
type Change struct{ Status KeyStatus }

type System struct {
	database *sql.DB
	key      *encryption.Key
	onChange func(Change)
}

//go:embed migrations/*.sql
var migrations embed.FS

// Open applies pending migrations. key is the application's master key;
// onChange runs after the key changes and must not block.
func Open(ctx context.Context, database *sql.DB, key *encryption.Key, onChange func(Change)) (*System, error) {
	if err := schema.Migrate(ctx, database, "email", migrations); err != nil {
		return nil, err
	}
	return &System{database: database, key: key, onChange: onChange}, nil
}

// SetAPIKey replaces the provider API key.
func (system *System) SetAPIKey(ctx context.Context, actor Actor, apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	length := utf8.RuneCountInString(apiKey)
	if length < 8 || length > 500 || strings.ContainsAny(apiKey, " \t\r\n") {
		return ErrInvalid
	}
	runes := []rune(apiKey)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := system.database.ExecContext(ctx, `INSERT INTO email_settings (id, api_key, last_four, created_by, created_at, updated_by, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET api_key = excluded.api_key, last_four = excluded.last_four, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		system.key.Encrypt(apiKeyLabel, apiKey), string(runes[len(runes)-4:]), actor.Subject, now, actor.Subject, now)
	if err != nil {
		return err
	}
	status, err := system.KeyStatus(ctx)
	if err != nil {
		return err
	}
	system.onChange(Change{Status: status})
	return nil
}

// KeyStatus reports whether the API key is set.
func (system *System) KeyStatus(ctx context.Context) (KeyStatus, error) {
	var status KeyStatus
	var updated string
	err := system.database.QueryRowContext(ctx, `SELECT last_four, updated_at FROM email_settings WHERE id = 1`).Scan(&status.LastFour, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyStatus{}, nil
	}
	if err != nil {
		return KeyStatus{}, err
	}
	status.Set = true
	status.UpdatedAt, err = time.Parse(time.RFC3339, updated)
	return status, err
}

// apiKey decrypts the stored key for a provider call. A real Send method
// would call it and pass the key to the provider; it never leaves the system.
func (system *System) apiKey(ctx context.Context) (string, error) {
	var sealed []byte
	err := system.database.QueryRowContext(ctx, `SELECT api_key FROM email_settings WHERE id = 1`).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotSet
	}
	if err != nil {
		return "", err
	}
	return system.key.Decrypt(apiKeyLabel, sealed)
}
