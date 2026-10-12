package websocket

import (
	"context"
	"net/http"

	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/userprofiles"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/realtime"
)

const NotesPattern = "GET /ws/notes"
const NotesTopic = "notes.changed"

// Notes subscribes the page to note changes. Mount it behind access.NotesRead.
func Notes(hub *realtime.Hub) http.Handler {
	return hub.Subscriber(NotesTopic)
}

// NewNotesPublisher sends each subscriber their view of every note change:
// {"note": {...}} for a saved note, {"id": 7, "removed": true} for a deleted
// one or one they may no longer see. Pass Add as the notes system's onChange,
// and start Run in a goroutine.
func NewNotesPublisher(hub *realtime.Hub, profiles *userprofiles.System) *realtime.Publisher[int64, notes.Change] {
	return realtime.NewPublisher(hub, NotesTopic,
		func(change notes.Change) int64 { return change.ID },
		func(ctx context.Context, change notes.Change) (realtime.View, error) {
			var author userprofiles.UserProfile // looked up once, not once per subscriber
			if change.Note != nil {
				authors, err := profiles.Lookup(ctx, []string{change.Note.AuthorSubject})
				if err != nil {
					return nil, err
				}
				author = authors[change.Note.AuthorSubject]
			}
			return func(person identity.Identity) ([]byte, bool) {
				if change.Note != nil {
					if view, ok := access.ViewNote(person, *change.Note, author); ok {
						return marshal(map[string]any{"note": view}, true)
					}
				}
				return marshal(map[string]any{"id": change.ID, "removed": true}, true)
			}, nil
		})
}
