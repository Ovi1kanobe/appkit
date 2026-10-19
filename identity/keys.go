package identity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Ovi1kanobe/appkit/api"
)

// A key is a personal API key a signed-in person makes for a tool, scoped to
// some of their own permissions, so the tool calls the app's routes as that
// person. The secret is shown once and stored as a hash, like a session
// cookie; the id is what lists and logs show.

const (
	keyPrefix       = "ak_"
	keyLength       = len(keyPrefix) + 43 // The prefix and a 32 byte secret in base64url.
	keyIDLength     = 12
	keyNameLength   = 64
	keysPerSubject  = 20
	keyRetention    = 30 * 24 * time.Hour // Revoked and expired keys stay listed this long.
	keyThrottle     = time.Minute         // Between last-used writes, and between warnings, per key.
	defaultKeyLife  = 30 * 24 * time.Hour
	longestKeyLife  = 90 * 24 * time.Hour
	keyAdminPattern = "/auth/users/{subject}/keys"
)

var (
	errUnknownKey    = errors.New("identity: unknown key")
	errKeysNotIssued = api.Invalid("This application does not issue keys.")
)

// keyRecord is one row of appkit_keys. Identity is the holder as of their last
// sign-in; KeyID is set from id when the record is read.
type keyRecord struct {
	Identity
	id, hash, name string
	scopes         []string
	created        time.Time
	expires        time.Time
	used, revoked  time.Time // Zero when never.
}

// keyStamp throttles the writes and warnings one key can cause.
type keyStamp struct{ used, warned time.Time }

type keyContextKey struct{}

func keyHash(value string) string { return digest("appkit/key/" + value) }

func keyFromContext(ctx context.Context) (keyRecord, bool) {
	record, ok := ctx.Value(keyContextKey{}).(keyRecord)
	return record, ok
}

// isKeyRequest reports whether a request presents a key: any Authorization
// header with the Bearer scheme. Other schemes are ignored, as they were.
func isKeyRequest(r *http.Request) bool {
	for _, header := range r.Header.Values("Authorization") {
		if fields := strings.Fields(header); len(fields) != 0 && strings.EqualFold(fields[0], "Bearer") {
			return true
		}
	}
	return false
}

// readKey checks the header's shape before any read, then looks the key up by
// its hash. Called with s.mu held.
func (s *Sessions) readKey(ctx context.Context, r *http.Request) (keyRecord, error) {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return keyRecord{}, errUnknownKey
	}
	fields := strings.Fields(headers[0])
	if len(fields) != 2 || len(fields[1]) != keyLength || !strings.HasPrefix(fields[1], keyPrefix) {
		return keyRecord{}, errUnknownKey
	}
	records, err := s.selectKeys(ctx, `WHERE hash=?`, keyHash(fields[1]))
	if err != nil {
		return keyRecord{}, err
	}
	if len(records) == 0 {
		return keyRecord{}, errUnknownKey
	}
	return records[0], nil
}

// admitKey serves a request that presents a key: refused with 401 when the key
// is unknown, revoked, expired, or left with no permission; otherwise served as
// the holder, with the key's id on the identity, until the key ends.
func (s *Sessions) admitKey(w http.ResponseWriter, r *http.Request, next http.Handler) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "Sign-in is unavailable.")
		return
	}
	record, err := s.readKey(r.Context(), r)
	if errors.Is(err, errUnknownKey) {
		// One line a minute for the whole process, keyed by nothing a client
		// chooses, so a flood of guesses shows in the log without filling it.
		if s.stampKey("", time.Now(), true) {
			slog.Warn("AppKit unknown key presented", "path", r.URL.Path)
		}
		s.mu.Unlock()
		refuseKey(w)
		return
	}
	if err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "Sign-in is unavailable.")
		return
	}
	now := time.Now()
	permissions := s.config.Policy.ResolveKey(record.Groups, record.scopes).Permissions()
	reason := ""
	switch {
	case !record.revoked.IsZero():
		reason = "revoked"
	case !now.Before(record.expires):
		reason = "expired"
	case len(permissions) == 0:
		reason = "no permissions left"
	}
	if reason != "" {
		if s.stampKey(record.id, now, true) {
			slog.Warn("AppKit key refused", "key", record.id, "subject", record.Subject, "reason", reason)
		}
		s.mu.Unlock()
		refuseKey(w)
		return
	}
	if s.stampKey(record.id, now, false) {
		if _, err = s.conn.ExecContext(r.Context(), `UPDATE appkit_keys SET used=? WHERE id=?`, now.UnixMilli(), record.id); err != nil {
			slog.Warn("AppKit key last use not recorded", "key", record.id, "error", err)
		}
	}
	person := record.Identity
	person.Permissions = permissions
	ctx, cancel := context.WithDeadline(WithContext(context.WithValue(r.Context(), keyContextKey{}, record), person), record.expires)
	release := s.watch(record.hash, cancel)
	s.mu.Unlock()
	defer release()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		slog.Info("AppKit key request", "method", r.Method, "path", r.URL.Path, "subject", record.Subject, "key", record.id)
	}
	next.ServeHTTP(w, r.WithContext(ctx))
}

func refuseKey(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "Key not accepted.")
}

// stampKey reports whether a key's last use (or its warning, when warn is set)
// may be recorded now, at most once a minute each, and remembers that it was.
// Entries idle for a minute are dropped, so the map holds only keys seen in
// the last minute. Called with s.mu held.
func (s *Sessions) stampKey(id string, now time.Time, warn bool) bool {
	for other, stamp := range s.keyStamps {
		if now.Sub(stamp.used) >= keyThrottle && now.Sub(stamp.warned) >= keyThrottle {
			delete(s.keyStamps, other)
		}
	}
	stamp := s.keyStamps[id]
	last := &stamp.used
	if warn {
		last = &stamp.warned
	}
	if now.Sub(*last) < keyThrottle {
		return false
	}
	*last = now
	s.keyStamps[id] = stamp
	return true
}

// delegableFor returns the permissions a person may give a key: the delegable
// ones the policy grants their groups. The same expression gates creation.
func (s *Sessions) delegableFor(person Identity) []string {
	return s.config.Policy.ResolveKey(person.Groups, s.config.Policy.Delegable()).Permissions()
}

// createKey makes a key for person and returns its record and the secret, the
// only time the secret exists in the clear. Called with s.mu held.
func (s *Sessions) createKey(ctx context.Context, person Identity, name string, scopes []string, lifetimeSeconds int64) (keyRecord, string, error) {
	delegable := s.delegableFor(person)
	if len(delegable) == 0 {
		return keyRecord{}, "", errKeysNotIssued
	}
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > keyNameLength {
		return keyRecord{}, "", api.Invalid(fmt.Sprintf("A key needs a name of up to %d characters.", keyNameLength))
	}
	if len(scopes) == 0 {
		return keyRecord{}, "", api.Invalid("A key needs at least one permission.")
	}
	scopes = slices.Compact(slices.Sorted(slices.Values(scopes)))
	for _, scope := range scopes {
		if !slices.Contains(delegable, scope) {
			return keyRecord{}, "", api.Invalid(fmt.Sprintf("You cannot give a key the permission %q.", scope))
		}
	}
	// The seconds are checked before they become a Duration, which a large
	// value would overflow into the accepted range.
	if lifetimeSeconds < 1 || lifetimeSeconds > int64(s.config.KeyLifetime/time.Second) {
		return keyRecord{}, "", api.Invalid("A key needs a lifetime of at least one second and at most " + describeLifetime(s.config.KeyLifetime) + ".")
	}
	lifetime := time.Duration(lifetimeSeconds) * time.Second
	now := time.Now()
	if err := s.pruneKeys(ctx, now); err != nil {
		return keyRecord{}, "", err
	}
	// Dead keys stay listed for a while, but never more than the cap of them
	// per person, so making and ending keys in a loop cannot grow the table.
	if _, err := s.conn.ExecContext(ctx, `DELETE FROM appkit_keys WHERE subject=? AND (revoked IS NOT NULL OR expires<=?) AND id NOT IN (SELECT id FROM appkit_keys WHERE subject=? AND (revoked IS NOT NULL OR expires<=?) ORDER BY created DESC LIMIT ?)`, person.Subject, now.UnixMilli(), person.Subject, now.UnixMilli(), keysPerSubject); err != nil {
		return keyRecord{}, "", err
	}
	var live int
	if err := s.conn.QueryRowContext(ctx, `SELECT count(*) FROM appkit_keys WHERE subject=? AND revoked IS NULL AND expires>?`, person.Subject, now.UnixMilli()).Scan(&live); err != nil {
		return keyRecord{}, "", err
	}
	if live >= keysPerSubject {
		return keyRecord{}, "", api.Conflict(fmt.Sprintf("You already have %d keys; revoke one first.", keysPerSubject))
	}
	secret := keyPrefix + randomSecret()
	record := keyRecord{Identity: Identity{Subject: person.Subject, Email: person.Email, Groups: person.Groups}, id: rand.Text()[:keyIDLength], hash: keyHash(secret), name: name, scopes: scopes, created: now, expires: now.Add(lifetime)}
	data, _ := json.Marshal(record.Identity)
	_, err := s.conn.ExecContext(ctx, `INSERT INTO appkit_keys(id,hash,subject,identity,name,scopes,created,expires) VALUES(?,?,?,?,?,?,?,?)`, record.id, record.hash, record.Subject, string(data), record.name, encodeScopes(record.scopes), record.created.UnixMilli(), record.expires.UnixMilli())
	if err != nil {
		return keyRecord{}, "", err
	}
	record.KeyID = record.id
	return record, secret, nil
}

// pruneKeys drops rows revoked or expired more than the retention ago.
func (s *Sessions) pruneKeys(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-keyRetention).UnixMilli()
	_, err := s.conn.ExecContext(ctx, `DELETE FROM appkit_keys WHERE (revoked IS NOT NULL AND revoked<?) OR expires<?`, cutoff, cutoff)
	return err
}

// keysOf lists a subject's keys, newest first. Called with s.mu held.
func (s *Sessions) keysOf(ctx context.Context, subject string) ([]keyRecord, error) {
	return s.selectKeys(ctx, `WHERE subject=? ORDER BY created DESC, id`, subject)
}

func (s *Sessions) selectKeys(ctx context.Context, where string, args ...any) ([]keyRecord, error) {
	rows, err := s.conn.QueryContext(ctx, `SELECT id, hash, subject, identity, name, scopes, created, expires, used, revoked FROM appkit_keys `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []keyRecord
	for rows.Next() {
		var record keyRecord
		var data, scopes string
		var created, expires int64
		var used, revoked sql.NullInt64
		if err := rows.Scan(&record.id, &record.hash, &record.Subject, &data, &record.name, &scopes, &created, &expires, &used, &revoked); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(data), &record.Identity) != nil {
			return nil, errors.New("identity: invalid key data")
		}
		record.KeyID = record.id
		record.scopes = decodeScopes(scopes)
		record.created, record.expires = time.UnixMilli(created), time.UnixMilli(expires)
		if used.Valid {
			record.used = time.UnixMilli(used.Int64)
		}
		if revoked.Valid {
			record.revoked = time.UnixMilli(revoked.Int64)
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// revokeKeys ends the live keys the where clause selects and returns how many
// there were; a key already revoked or expired is left as it is. Called with
// s.mu held.
func (s *Sessions) revokeKeys(ctx context.Context, where string, args ...any) (int, error) {
	now := time.Now()
	if err := s.pruneKeys(ctx, now); err != nil {
		return 0, err
	}
	records, err := s.selectKeys(ctx, where+` AND revoked IS NULL AND expires>?`, append(args, now.UnixMilli())...)
	if err != nil || len(records) == 0 {
		return 0, err
	}
	for _, record := range records {
		if _, err = s.conn.ExecContext(ctx, `UPDATE appkit_keys SET revoked=? WHERE id=?`, now.UnixMilli(), record.id); err != nil {
			return 0, err
		}
		s.cancelSession(record.hash)
	}
	return len(records), nil
}

// refreshKeys gives the holder's keys their identity as of this sign-in and
// ends the live requests of any key whose permissions changed, so a tool
// reconnects with the new ones. Called with s.mu held.
func (s *Sessions) refreshKeys(ctx context.Context, person Identity) error {
	records, err := s.selectKeys(ctx, `WHERE subject=? AND revoked IS NULL`, person.Subject)
	if err != nil || len(records) == 0 {
		return err
	}
	data, _ := json.Marshal(Identity{Subject: person.Subject, Email: person.Email, Groups: person.Groups})
	if _, err = s.conn.ExecContext(ctx, `UPDATE appkit_keys SET identity=? WHERE subject=?`, string(data), person.Subject); err != nil {
		return err
	}
	for _, record := range records {
		before := s.config.Policy.ResolveKey(record.Groups, record.scopes).Permissions()
		after := s.config.Policy.ResolveKey(person.Groups, record.scopes).Permissions()
		if !slices.Equal(before, after) {
			s.cancelSession(record.hash)
		}
	}
	return nil
}

func encodeScopes(scopes []string) string {
	data, _ := json.Marshal(scopes)
	return string(data)
}

func decodeScopes(data string) []string {
	var scopes []string
	_ = json.Unmarshal([]byte(data), &scopes)
	return scopes
}

// describeLifetime says a lifetime in days when it has whole days, else in hours.
func describeLifetime(lifetime time.Duration) string {
	if lifetime >= 24*time.Hour && lifetime%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", lifetime/(24*time.Hour))
	}
	return fmt.Sprintf("%.0f hours", lifetime.Hours())
}
