package websocket

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

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
	return subscribe(hub, NotesTopic)
}

// NotesPublisher sends each subscriber their view of every note change:
// {"note": {...}} for a new note, {"id": 7, "removed": true} for a deleted one.
// Pass Add as the notes system's onChange, and start Run in a goroutine.
type NotesPublisher struct {
	hub      *realtime.Hub
	profiles *userprofiles.System
	mutex    sync.Mutex
	pending  map[int64]notes.Change
	signal   chan struct{}
}

func NewNotesPublisher(hub *realtime.Hub, profiles *userprofiles.System) *NotesPublisher {
	return &NotesPublisher{hub: hub, profiles: profiles, pending: map[int64]notes.Change{}, signal: make(chan struct{}, 1)}
}

// Add never blocks a request. It keeps the latest change per note until Run sends it.
func (publisher *NotesPublisher) Add(change notes.Change) {
	publisher.mutex.Lock()
	publisher.pending[change.ID] = change
	publisher.mutex.Unlock()
	select {
	case publisher.signal <- struct{}{}:
	default:
	}
}

// Run publishes pending changes until ctx ends.
func (publisher *NotesPublisher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-publisher.signal:
			publisher.mutex.Lock()
			pending := publisher.pending
			publisher.pending = map[int64]notes.Change{}
			publisher.mutex.Unlock()
			for _, change := range pending {
				var author userprofiles.UserProfile
				if change.Note != nil {
					authorProfiles, err := publisher.profiles.Lookup(ctx, []string{change.Note.AuthorSubject})
					if err != nil {
						slog.ErrorContext(ctx, "note author profile", "error", err)
						continue
					}
					author = authorProfiles[change.Note.AuthorSubject]
				}
				publishEach(ctx, publisher.hub, NotesTopic, func(person identity.Identity) ([]byte, bool) {
					return noteMessage(person, change, author)
				})
			}
		}
	}
}

// noteMessage is what person receives for change: the note as they see it, or
// its removal when it was deleted or they may no longer see it.
func noteMessage(person identity.Identity, change notes.Change, author userprofiles.UserProfile) ([]byte, bool) {
	if change.Note != nil {
		if view, ok := access.ViewNote(person, *change.Note, author); ok {
			return marshal(map[string]any{"note": view}, true)
		}
	}
	return marshal(map[string]any{"id": change.ID, "removed": true}, true)
}
