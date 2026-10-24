// Package access holds every rule about who may do and see what. HTTP routes
// and WebSocket publishers both use it, so each rule exists once.
package access

import (
	"time"

	"github.com/Ovi1kanobe/appkit/api"

	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/userprofiles"
	"github.com/Ovi1kanobe/appkit/identity"
)

// Route permissions for notes.
const (
	NotesRead  = "notes.read"
	NotesWrite = "notes.write"
)

var ErrNotAuthor = api.Forbidden("Only the author may delete this note.")

// Note is what a person sees of a note: the note, its author's current email,
// and whether it is theirs.
type Note struct {
	notes.Note
	AuthorEmail string `json:"author_email"`
	Mine        bool   `json:"mine"`
}

// ViewNote returns what viewer sees of note, given its author's profile.
// Everyone who reads notes sees every note. A note a visitor posted through
// the public route has identity.PublicSubject as its author, who has no
// profile, so its author email is empty and it is no one's.
func ViewNote(viewer identity.Identity, note notes.Note, author userprofiles.UserProfile) (Note, bool) {
	return Note{Note: note, AuthorEmail: author.Email, Mine: note.CreatedBy == viewer.Subject}, true
}

// PublicNote is what anyone sees of a note, signed in or not: its text and
// when it was written, never who wrote it. Each field is listed here, so a
// field added to notes.Note is never public by accident.
type PublicNote struct {
	ID        int64     `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// ViewPublicNote returns what anyone sees of note. Every note is public today;
// false would leave it out of a list and answer not found for one note.
func ViewPublicNote(note notes.Note) (PublicNote, bool) {
	return PublicNote{ID: note.ID, Text: note.Text, CreatedAt: note.CreatedAt}, true
}

// CanDeleteNote reports whether viewer may delete note: only its author may.
func CanDeleteNote(viewer identity.Identity, note notes.Note) bool {
	return note.CreatedBy == viewer.Subject
}
