package http

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/userprofiles"
	"github.com/Ovi1kanobe/appkit/identity"
)

const (
	ListNotesPattern  = "GET /api/notes"
	CreateNotePattern = "POST /api/notes"
	DeleteNotePattern = "DELETE /api/notes/{id}"
)

// viewer is the signed-in person making the request.
func viewer(request *http.Request) identity.Identity {
	person, _ := identity.FromContext(request.Context())
	return person
}

// ListNotes serves every note as the viewer sees it. Mount it behind access.NotesRead.
func ListNotes(system *notes.System, profiles *userprofiles.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		list, err := system.List(request.Context())
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		authors := make([]string, 0, len(list))
		for _, note := range list {
			authors = append(authors, note.CreatedBy)
		}
		authorProfiles, err := profiles.Lookup(request.Context(), authors)
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		views := []access.Note{}
		for _, note := range list {
			if view, ok := access.ViewNote(viewer(request), note, authorProfiles[note.CreatedBy]); ok {
				views = append(views, view)
			}
		}
		api.WriteJSON(writer, http.StatusOK, views)
	})
}

// CreateNote adds a note from {"text"}. Mount it behind access.NotesWrite.
func CreateNote(system *notes.System, profiles *userprofiles.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Text string `json:"text"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 4096)).Decode(&input); err != nil {
			api.WriteError(writer, request, notes.ErrInvalid)
			return
		}
		person := viewer(request)
		note, err := system.Create(request.Context(), notes.Actor{Subject: person.Subject}, input.Text)
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		authorProfiles, err := profiles.Lookup(request.Context(), []string{person.Subject})
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		view, _ := access.ViewNote(person, note, authorProfiles[person.Subject])
		api.WriteJSON(writer, http.StatusCreated, view)
	})
}

// DeleteNote removes a note its author may delete. Mount it behind access.NotesWrite.
func DeleteNote(system *notes.System) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		id, err := strconv.ParseInt(request.PathValue("id"), 10, 64)
		if err != nil {
			api.WriteError(writer, request, notes.ErrNotFound)
			return
		}
		note, err := system.Get(request.Context(), id)
		if err != nil {
			api.WriteError(writer, request, err)
			return
		}
		if !access.CanDeleteNote(viewer(request), note) {
			api.WriteError(writer, request, access.ErrNotAuthor)
			return
		}
		if err := system.Delete(request.Context(), id); err != nil {
			api.WriteError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}
