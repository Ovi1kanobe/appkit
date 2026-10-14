// Package userprofiles owns what the application knows about each person who
// has signed in. A profile is recorded at every signed-in session request, so
// one exists before any page loads and its email stays current. Records that
// belong to a person store the subject only and look the profile up to show them.
package userprofiles

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"strings"
	"time"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/schema"
)

var ErrInvalid = api.Invalid("A profile needs a subject.")

// UserProfile is what the application knows about one person.
type UserProfile struct {
	Subject string `json:"-"`
	Email   string `json:"email"`
}

type System struct {
	database *sql.DB
}

//go:embed migrations/*.sql
var migrations embed.FS

// Open applies pending migrations.
func Open(ctx context.Context, database *sql.DB) (*System, error) {
	if err := schema.Migrate(ctx, database, "userprofiles", migrations); err != nil {
		return nil, err
	}
	return &System{database: database}, nil
}

// Record creates or refreshes the profile for subject.
func (system *System) Record(ctx context.Context, subject, email string) error {
	if strings.TrimSpace(subject) == "" {
		return ErrInvalid
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := system.database.ExecContext(ctx,
		`INSERT INTO user_profiles (subject, email, created_at, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (subject) DO UPDATE SET email = excluded.email, updated_at = excluded.updated_at`,
		subject, email, now, now)
	return err
}

// Lookup returns the profiles for subjects, keyed by subject. A person who has
// never signed in is absent from the result.
func (system *System) Lookup(ctx context.Context, subjects []string) (map[string]UserProfile, error) {
	profiles := map[string]UserProfile{}
	for _, subject := range subjects {
		if _, done := profiles[subject]; done {
			continue
		}
		var profile UserProfile
		err := system.database.QueryRowContext(ctx, `SELECT subject, email FROM user_profiles WHERE subject = ?`, subject).Scan(&profile.Subject, &profile.Email)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		profiles[subject] = profile
	}
	return profiles, nil
}
