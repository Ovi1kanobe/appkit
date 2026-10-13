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

	"github.com/Ovi1kanobe/appkit/schema"
)

var (
	ErrInvalid  = errors.New("A note needs between 1 and 500 characters.")
	ErrNotFound = errors.New("That note no longer exists.")
)

const maximumLength = 500

// Actor is the person creating a note, recorded as its author by subject.
type Actor struct{ Subject string }

type Note struct {
	ID        int64     `json:"id"`
	Text      string    `json:"text"`
	CreatedBy string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
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

func (system *System) Create(ctx context.Context, actor Actor, text string) (Note, error) {
	text = strings.TrimSpace(text)
	if text == "" || utf8.RuneCountInString(text) > maximumLength {
		return Note{}, ErrInvalid
	}
	note := Note{Text: text, CreatedBy: actor.Subject, CreatedAt: time.Now().UTC().Truncate(time.Second)}
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
