// Package notes owns a shared list of short notes. It checks no permissions;
// api/access decides who may see and delete them.
package notes

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/schema"
)

var (
	ErrInvalid       = api.Invalid("A note needs between 1 and 500 characters.")
	ErrNoRequestID   = api.Invalid("A create needs a request_id.")
	ErrRequestIDUsed = api.Conflict("That request_id was already used for another create.")
	ErrNotFound      = api.NotFound("That note no longer exists.")
)

const maximumLength = 500

// Actor is who creates or deletes a note, recorded by subject: a person, or
// the public subject the transport passes for a visitor who is not signed in.
type Actor struct{ Subject string }

type Note struct {
	ID        int64
	Text      string
	CreatedBy string
	CreatedAt time.Time
}

// Change is a created note, or a deleted note's ID with Note nil, with when
// and by whom, as a subject, it changed.
type Change struct {
	ID   int64
	Note *Note
	At   time.Time
	By   string
}

type System struct {
	database *sql.DB
	onChange func(Change)
}

//go:embed migrations/*.sql
var migrations embed.FS

// Open applies pending migrations. onChange runs after every committed change
// and must not block.
func Open(ctx context.Context, database *sql.DB, onChange func(Change)) (*System, error) {
	if err := schema.Migrate(ctx, database, "notes", migrations); err != nil {
		return nil, err
	}
	return &System{database: database, onChange: onChange}, nil
}

// noteColumns are the columns scanNote reads, in its order, for every query
// that returns notes.
const noteColumns = `id, text, created_by, created_at`

// scanNote reads one row of noteColumns from a *sql.Row or *sql.Rows.
func scanNote(row interface{ Scan(...any) error }) (Note, error) {
	var note Note
	var created string
	if err := row.Scan(&note.ID, &note.Text, &note.CreatedBy, &created); err != nil {
		return Note{}, err
	}
	var err error
	note.CreatedAt, err = time.Parse(time.RFC3339, created)
	return note, err
}

func (system *System) List(ctx context.Context) ([]Note, error) {
	rows, err := system.database.QueryContext(ctx, `SELECT `+noteColumns+` FROM notes ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	notes := []Note{}
	for rows.Next() {
		note, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}
	return notes, rows.Err()
}

// validRequestID returns ErrNoRequestID when the client sent no request id.
func validRequestID(requestID string) error {
	if requestID == "" {
		return ErrNoRequestID
	}
	return nil
}

// validText returns text without surrounding space, or ErrInvalid when
// nothing is left or it is longer than maximumLength characters.
func validText(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" || utf8.RuneCountInString(text) > maximumLength {
		return "", ErrInvalid
	}
	return text, nil
}

// newNote is the note actor creates with text at now, which is stored to the
// second. It has no ID until it is inserted.
func newNote(actor Actor, text string, now time.Time) Note {
	return Note{Text: text, CreatedBy: actor.Subject, CreatedAt: now.UTC().Truncate(time.Second)}
}

// Create adds a note. requestID is the client's id for this create: a repeat
// by the same actor with the id of a note already created returns that note
// and changes nothing, so a client may retry a create it heard no answer to;
// the id from another actor returns ErrRequestIDUsed. Every visitor is the
// public subject, so a visitor's replay returns the same note.
func (system *System) Create(ctx context.Context, actor Actor, requestID string, text string) (Note, error) {
	if err := validRequestID(requestID); err != nil {
		return Note{}, err
	}
	text, err := validText(text)
	if err != nil {
		return Note{}, err
	}
	note := newNote(actor, text, time.Now())
	created := note.CreatedAt.Format(time.RFC3339)
	result, err := system.database.ExecContext(ctx, `INSERT INTO notes (text, created_by, created_at, updated_by, updated_at, request_id) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (request_id) DO NOTHING`,
		note.Text, note.CreatedBy, created, note.CreatedBy, created, requestID)
	if err != nil {
		return Note{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Note{}, err
	}
	if inserted == 0 {
		existing, err := scanNote(system.database.QueryRowContext(ctx, `SELECT `+noteColumns+` FROM notes WHERE request_id = ? AND created_by = ?`, requestID, actor.Subject))
		if errors.Is(err, sql.ErrNoRows) {
			return Note{}, ErrRequestIDUsed
		}
		return existing, err
	}
	if note.ID, err = result.LastInsertId(); err != nil {
		return Note{}, err
	}
	slog.Info("note created", "subject", actor.Subject, "note", note.ID)
	system.onChange(Change{ID: note.ID, Note: &note, At: note.CreatedAt, By: actor.Subject})
	return note, nil
}

// Get returns one note.
func (system *System) Get(ctx context.Context, id int64) (Note, error) {
	note, err := scanNote(system.database.QueryRowContext(ctx, `SELECT `+noteColumns+` FROM notes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Note{}, ErrNotFound
	}
	return note, err
}

// Delete removes a note.
func (system *System) Delete(ctx context.Context, actor Actor, id int64) error {
	now := time.Now()
	result, err := system.database.ExecContext(ctx, `DELETE FROM notes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if removed, err := result.RowsAffected(); err != nil || removed == 0 {
		return ErrNotFound
	}
	slog.Info("note deleted", "subject", actor.Subject, "note", id)
	system.onChange(Change{ID: id, At: now.UTC().Truncate(time.Second), By: actor.Subject})
	return nil
}
