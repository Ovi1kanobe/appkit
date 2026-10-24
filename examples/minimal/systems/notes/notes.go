// Package notes owns a shared list of short notes. It checks no permissions;
// api/access decides who may see and delete them.
package notes

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/schema"
)

var (
	ErrInvalid  = api.Invalid("A note needs between 1 and 500 characters.")
	ErrNotFound = api.NotFound("That note no longer exists.")
)

const maximumLength = 500

// Actor is who creates a note, recorded as its author by subject: a person,
// or the public subject the transport passes for a visitor who is not signed
// in.
type Actor struct{ Subject string }

type Note struct {
	ID        int64
	Text      string
	CreatedBy string
	CreatedAt time.Time
}

// Change is a created note, or a deleted note's ID with Note nil.
type Change struct {
	ID   int64
	Note *Note
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

func (system *System) List(ctx context.Context) ([]Note, error) {
	rows, err := system.database.QueryContext(ctx, `SELECT id, text, created_by, created_at FROM notes ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	notes := []Note{}
	for rows.Next() {
		var note Note
		var created string
		if err := rows.Scan(&note.ID, &note.Text, &note.CreatedBy, &created); err != nil {
			return nil, err
		}
		if note.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}
	return notes, rows.Err()
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

func (system *System) Create(ctx context.Context, actor Actor, text string) (Note, error) {
	text, err := validText(text)
	if err != nil {
		return Note{}, err
	}
	note := newNote(actor, text, time.Now())
	created := note.CreatedAt.Format(time.RFC3339)
	result, err := system.database.ExecContext(ctx, `INSERT INTO notes (text, created_by, created_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?)`,
		note.Text, actor.Subject, created, actor.Subject, created)
	if err != nil {
		return Note{}, err
	}
	if note.ID, err = result.LastInsertId(); err != nil {
		return Note{}, err
	}
	system.onChange(Change{ID: note.ID, Note: &note})
	return note, nil
}

// Get returns one note.
func (system *System) Get(ctx context.Context, id int64) (Note, error) {
	var note Note
	var created string
	err := system.database.QueryRowContext(ctx, `SELECT id, text, created_by, created_at FROM notes WHERE id = ?`, id).
		Scan(&note.ID, &note.Text, &note.CreatedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Note{}, ErrNotFound
	}
	if err != nil {
		return Note{}, err
	}
	note.CreatedAt, err = time.Parse(time.RFC3339, created)
	return note, err
}

// Delete removes a note.
func (system *System) Delete(ctx context.Context, id int64) error {
	result, err := system.database.ExecContext(ctx, `DELETE FROM notes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if removed, err := result.RowsAffected(); err != nil || removed == 0 {
		return ErrNotFound
	}
	system.onChange(Change{ID: id})
	return nil
}
