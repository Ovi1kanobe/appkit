package identity

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Ovi1kanobe/appkit/api"
)

// keyView is a key as /auth/keys answers it: never the secret or its hash.
// Permissions is what the key gets now, which a narrowed key shows plainly.
type keyView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

func (s *Sessions) viewKey(record keyRecord) keyView {
	view := keyView{ID: record.id, Name: record.name, Scopes: record.scopes, Permissions: s.config.Policy.ResolveKey(record.Groups, record.scopes).Permissions(), CreatedAt: record.created.UTC(), ExpiresAt: record.expires.UTC()}
	if !record.used.IsZero() {
		used := record.used.UTC()
		view.LastUsedAt = &used
	}
	if !record.revoked.IsZero() {
		revoked := record.revoked.UTC()
		view.RevokedAt = &revoked
	}
	return view
}

func (s *Sessions) viewKeys(records []keyRecord) []keyView {
	views := make([]keyView, 0, len(records))
	for _, record := range records {
		views = append(views, s.viewKey(record))
	}
	return views
}

// keyRoutes mounts key management: a person's own keys, and when the app names
// a permission for it, any person's keys behind that permission. A key cannot
// reach any of them.
func (s *Sessions) keyRoutes(mux *http.ServeMux) {
	mux.Handle("GET /auth/keys", s.require(s.browserOnly(s.listKeys)))
	mux.Handle("POST /auth/keys", api.LimitBody(4<<10, s.require(s.browserOnly(s.createKeyHandler))))
	mux.Handle("DELETE /auth/keys/{id}", s.require(s.browserOnly(s.revokeKeyHandler)))
	permission := s.config.KeyAdminPermission
	if permission == "" {
		return
	}
	mux.Handle("GET "+keyAdminPattern, s.require(requirePermission(permission, s.browserOnly(s.listSubjectKeys))))
	mux.Handle("DELETE "+keyAdminPattern, s.require(requirePermission(permission, s.browserOnly(s.revokeSubjectKeys))))
	mux.Handle("DELETE "+keyAdminPattern+"/{id}", s.require(requirePermission(permission, s.browserOnly(s.revokeSubjectKey))))
}

// browserOnly refuses a request a key made, so a key can never mint, list, or
// revoke keys.
func (s *Sessions) browserOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if person, _ := FromContext(r.Context()); person.KeyID != "" {
			writeError(w, http.StatusForbidden, "Keys are managed from a browser session.")
			return
		}
		next(w, r)
	})
}

func (s *Sessions) listKeys(w http.ResponseWriter, r *http.Request) {
	person, _ := FromContext(r.Context())
	s.answerKeys(w, r, person.Subject)
}

func (s *Sessions) listSubjectKeys(w http.ResponseWriter, r *http.Request) {
	s.answerKeys(w, r, r.PathValue("subject"))
}

// errClosed answers a request that arrives while Sessions is closing.
var errClosed = api.Unavailable("Sign-in is unavailable.")

func (s *Sessions) answerKeys(w http.ResponseWriter, r *http.Request, subject string) {
	s.mu.Lock()
	records, err := []keyRecord(nil), errClosed
	if !s.closed {
		records, err = s.keysOf(r.Context(), subject)
	}
	s.mu.Unlock()
	if err != nil {
		api.WriteError(w, r, err)
		return
	}
	api.WriteJSON(w, http.StatusOK, map[string]any{"keys": s.viewKeys(records)})
}

func (s *Sessions) createKeyHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name            string   `json:"name"`
		Scopes          []string `json:"scopes"`
		LifetimeSeconds int64    `json:"lifetime_seconds"`
	}
	if err := api.ReadJSON(r, &body); err != nil {
		api.WriteError(w, r, err)
		return
	}
	person, _ := FromContext(r.Context())
	s.mu.Lock()
	record, secret, err := keyRecord{}, "", errClosed
	if !s.closed {
		record, secret, err = s.createKey(r.Context(), person, body.Name, body.Scopes, body.LifetimeSeconds)
	}
	s.mu.Unlock()
	if err != nil {
		api.WriteError(w, r, err)
		return
	}
	slog.Info("AppKit key created", "subject", record.Subject, "key", record.id, "name", record.name, "scopes", record.scopes, "expires", record.expires.UTC())
	api.WriteJSON(w, http.StatusCreated, map[string]any{"key": s.viewKey(record), "secret": secret})
}

func (s *Sessions) revokeKeyHandler(w http.ResponseWriter, r *http.Request) {
	person, _ := FromContext(r.Context())
	s.revoke(w, r, person.Subject, `WHERE subject=? AND id=?`, person.Subject, r.PathValue("id"))
}

func (s *Sessions) revokeSubjectKey(w http.ResponseWriter, r *http.Request) {
	s.revoke(w, r, r.PathValue("subject"), `WHERE subject=? AND id=?`, r.PathValue("subject"), r.PathValue("id"))
}

func (s *Sessions) revokeSubjectKeys(w http.ResponseWriter, r *http.Request) {
	s.revoke(w, r, r.PathValue("subject"), `WHERE subject=?`, r.PathValue("subject"))
}

// revoke ends the keys the clause selects and answers 204 whether or not any
// were live, so a missing or someone else's id tells nothing.
func (s *Sessions) revoke(w http.ResponseWriter, r *http.Request, subject, where string, args ...any) {
	actor, _ := FromContext(r.Context())
	s.mu.Lock()
	count, err := 0, errClosed
	if !s.closed {
		count, err = s.revokeKeys(r.Context(), where, args...)
	}
	s.mu.Unlock()
	if err != nil {
		api.WriteError(w, r, err)
		return
	}
	if count != 0 {
		slog.Info("AppKit keys revoked", "subject", subject, "count", count, "by", actor.Subject)
	}
	w.WriteHeader(http.StatusNoContent)
}
