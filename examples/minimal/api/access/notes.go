// Package access holds every rule about who may do and see what. HTTP routes
// and WebSocket publishers both use it, so each rule exists once.
package access

import (
	"errors"

	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/userprofiles"
	"github.com/Ovi1kanobe/appkit/identity"
)

// Route permissions for notes.
const (
	NotesRead  = "notes.read"
	NotesWrite = "notes.write"
)

var ErrNotAuthor = errors.New("Only the author may delete this note.")

// Note is what a person sees of a note: the note, its author's current email,
// and whether it is theirs.
type Note struct {
	notes.Note
	AuthorEmail string `json:"author_email"`
	Mine        bool   `json:"mine"`
}

// ViewNote returns what viewer sees of note, given its author's profile.
// Everyone who reads notes sees every note.
func ViewNote(viewer identity.Identity, note notes.Note, author userprofiles.UserProfile) (Note, bool) {
	return Note{Note: note, AuthorEmail: author.Email, Mine: note.CreatedBy == viewer.Subject}, true
}

// CanDeleteNote reports whether viewer may delete note: only its author may.
func CanDeleteNote(viewer identity.Identity, note notes.Note) bool {
	return note.CreatedBy == viewer.Subject
}
