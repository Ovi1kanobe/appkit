package http

import (
	"net/http"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/identity"
)

const (
	PublicNotesPattern      = "GET /api/notes/public"
	CreatePublicNotePattern = "POST /api/notes/public"
)

// PublicNotes serves every note as anyone sees it, signed in or not, through
// access.ViewPublicNote. Mount it public.
func PublicNotes(system *notes.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		list, err := system.List(request.Context())
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		views := []access.PublicNote{}
		for _, note := range list {
			if view, ok := access.ViewPublicNote(note); ok {
				views = append(views, view)
			}
		}
		api.WriteJSON(writer, http.StatusOK, views)
	})
}

// CreatePublicNote adds a note from {"text"} as identity.PublicSubject, for a
// visitor who is not signed in, and answers what anyone sees of it. Mount it
// public with its Origin.
func CreatePublicNote(system *notes.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Text string `json:"text"`
		}
		if err := api.ReadJSON(request, &input); err != nil {
			api.WriteError(writer, request, err)
			return
		}
		note, err := system.Create(request.Context(), notes.Actor{Subject: identity.PublicSubject}, input.Text)
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		view, _ := access.ViewPublicNote(note)
		api.WriteJSON(writer, http.StatusCreated, view)
	})
}
