package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Ovi1kanobe/appkit/authz"
	"modernc.org/sqlite"
)

// SessionConfig configures browser sessions.
// DatabasePath must name a dedicated, local file; AppKit owns its schema and lock.
type SessionConfig struct {
	Issuer, ClientID, ClientSecret string
	Origin                         string // Public origin, e.g. https://app.example.com or http://localhost:8080.
	DatabasePath                   string
	Policy                         *authz.Policy
	Lifetime                       time.Duration // Zero means eight hours; fixed from sign-in, never sliding.
	// KeyLifetime caps how long a personal key may live. Zero means thirty
	// days; more than ninety is refused, so a leaked key dies on its own
	// within a quarter.
	KeyLifetime time.Duration
	// KeyAdminPermission, when set, serves /auth/users/{subject}/keys behind
	// it, so a page may list and revoke another person's keys. Unset, the
	// routes are not served.
	KeyAdminPermission string
	// OnSessionRequest, when set, runs on each signed-in /auth/session request, which
	// every page makes as it loads, so the app can record that the person is here.
	// What it returns is sent as "app", so pages load per-person state in the same
	// request; an error answers 503.
	OnSessionRequest func(r *http.Request, actor Identity) (any, error)
}

// Sessions owns browser authentication, personal keys, and its SQLite
// connection. Call Close on shutdown. Use Verifier separately for bearer
// routes: Require and Optional accept a session cookie or a key, Bearer a
// Rauthy access token, and each refuses the other credentials.
type Sessions struct {
	config     SessionConfig
	verifier   *Verifier
	db         *sql.DB
	conn       *sql.Conn // Pinned for the lifetime of the exclusive SQLite lock.
	origin     *url.URL
	cookieName string
	mu         sync.Mutex // Serializes persistence, callback admission, and live request registration.
	closed     bool
	flows      map[string]loginFlow
	watches    map[string]map[*sessionWatch]struct{}
	keyStamps  map[string]keyStamp
}

type loginFlow struct {
	browser, nonce, verifier, next string
	started                        time.Time
}

type sessionWatch struct{ cancel context.CancelFunc }
type sessionRecord struct {
	Identity
	hash, sid string
	expires   time.Time
}

type sqliteConnector struct {
	driver driver.Driver
	path   string
}

func (c sqliteConnector) Connect(context.Context) (driver.Conn, error) { return c.driver.Open(c.path) }
func (c sqliteConnector) Driver() driver.Driver                        { return c.driver }

// NewSessions discovers Rauthy and opens AppKit's session database. A second
// process opening this database fails at startup. No goroutine or server is started.
func NewSessions(ctx context.Context, config SessionConfig) (*Sessions, error) {
	u, err := url.Parse(config.Origin)
	if err != nil || !secureURL(u) || u.RawQuery != "" || u.Path != "" && u.Path != "/" || config.Policy == nil {
		return nil, errors.New("identity: sessions need a valid HTTPS origin (HTTP only on localhost) and a policy")
	}
	u.Path = ""
	config.Origin = u.String()
	if config.Lifetime == 0 {
		config.Lifetime = 8 * time.Hour
	}
	if config.Lifetime < time.Second {
		return nil, errors.New("identity: session lifetime must be at least one second")
	}
	if config.KeyLifetime == 0 {
		config.KeyLifetime = defaultKeyLife
	}
	if config.KeyLifetime < time.Second || config.KeyLifetime > longestKeyLife {
		return nil, errors.New("identity: key lifetime must be between one second and ninety days")
	}
	if config.DatabasePath == "" || strings.ContainsAny(config.DatabasePath, "?\x00") || strings.HasPrefix(config.DatabasePath, "file:") || config.DatabasePath == ":memory:" {
		return nil, errors.New("identity: a dedicated session database file is required")
	}
	path, err := filepath.Abs(config.DatabasePath)
	if err != nil {
		return nil, errors.New("identity: invalid session database path")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("identity: cannot open session database")
	}
	err = file.Chmod(0600)
	_ = file.Close()
	if err != nil {
		return nil, errors.New("identity: cannot secure session database permissions")
	}
	v, err := New(ctx, Config{Issuer: config.Issuer, ClientID: config.ClientID})
	if err != nil {
		return nil, err
	}
	var metadata struct {
		Backchannel bool `json:"backchannel_logout_supported"`
	}
	if v.provider.Claims(&metadata) != nil || !metadata.Backchannel {
		return nil, errors.New("identity: provider must support back-channel logout")
	}
	for _, endpoint := range []string{v.provider.Endpoint().AuthURL, v.provider.Endpoint().TokenURL} {
		u, err := url.Parse(endpoint)
		if err != nil || !secureURL(u) {
			return nil, errors.New("identity: invalid provider endpoint")
		}
	}
	s := &Sessions{config: config, verifier: v, origin: u, cookieName: "__Host-appkit", flows: make(map[string]loginFlow), watches: make(map[string]map[*sessionWatch]struct{}), keyStamps: make(map[string]keyStamp)}
	if u.Scheme == "http" {
		s.cookieName = "appkit_local"
	}
	s.db = sql.OpenDB(sqliteConnector{&sqlite.Driver{}, path})
	s.db.SetMaxOpenConns(1)
	s.conn, err = s.db.Conn(ctx)
	if err != nil {
		_ = s.db.Close()
		return nil, errors.New("identity: cannot connect to session database")
	}
	// EXCLUSIVE mode retains the write lock after COMMIT until this connection
	// closes. Unlike a lease, it cannot expire while another process is still live.
	for _, statement := range []string{
		"PRAGMA busy_timeout=0", "PRAGMA locking_mode=EXCLUSIVE", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA secure_delete=ON", "BEGIN EXCLUSIVE",
		`CREATE TABLE IF NOT EXISTS appkit_sessions (hash TEXT PRIMARY KEY, subject TEXT NOT NULL, sid TEXT NOT NULL, identity TEXT NOT NULL, expires INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS appkit_logouts (hash TEXT PRIMARY KEY, subject TEXT NOT NULL, sid TEXT NOT NULL, issued INTEGER NOT NULL, received INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS appkit_provider (id INTEGER PRIMARY KEY CHECK(id=1), issuer TEXT NOT NULL, client TEXT NOT NULL, origin TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS appkit_keys (id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, subject TEXT NOT NULL, identity TEXT NOT NULL, name TEXT NOT NULL, scopes TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER, revoked INTEGER)`,
		"COMMIT",
	} {
		if _, err = s.conn.ExecContext(ctx, statement); err != nil {
			_ = s.Close()
			return nil, errors.New("identity: cannot exclusively open session database; another process may already be using it")
		}
	}
	if err = s.migrate(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	_, err = s.conn.ExecContext(ctx, `INSERT OR IGNORE INTO appkit_provider VALUES(1,?,?,?)`, config.Issuer, config.ClientID, config.Origin)
	var issuer, client, origin string
	if err == nil {
		err = s.conn.QueryRowContext(ctx, `SELECT issuer, client, origin FROM appkit_provider WHERE id=1`).Scan(&issuer, &client, &origin)
	}
	if err != nil || issuer != config.Issuer || client != config.ClientID || origin != config.Origin {
		_ = s.Close()
		return nil, errors.New("identity: session database belongs to another issuer, client, or origin")
	}
	return s, nil
}

// sessionSchemaVersion is the session database schema this AppKit writes. A
// schema change raises it: a new table is added to the startup list above, and
// a change to an existing table is a step in migrate. Version 2 added keys.
const sessionSchemaVersion = 2

// migrate records the schema version, and refuses a database written by a newer
// AppKit instead of misreading it.
func (s *Sessions) migrate(ctx context.Context) error {
	var version int
	if err := s.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return errors.New("identity: cannot read session database version")
	}
	if version > sessionSchemaVersion {
		return fmt.Errorf("identity: session database version %d is newer than this AppKit supports (%d)", version, sessionSchemaVersion)
	}
	if version < sessionSchemaVersion {
		if _, err := s.conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", sessionSchemaVersion)); err != nil {
			return errors.New("identity: cannot record session database version")
		}
	}
	return nil
}

// Close cancels live authenticated requests, including WebSockets, and releases
// the database lock. Durable sessions remain usable after restart until expiry.
func (s *Sessions) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, watches := range s.watches {
		for w := range watches {
			w.cancel()
		}
	}
	var err error
	if s.conn != nil {
		err = s.conn.Close()
	}
	return errors.Join(err, s.db.Close())
}

func randomSecret() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func digest(value string) string {
	b := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func cookieHash(value string) string { return digest("appkit/session/" + value) }

func (s *Sessions) readSession(ctx context.Context, raw string) (sessionRecord, error) {
	var record sessionRecord
	if len(raw) != 43 {
		return record, sql.ErrNoRows
	}
	record.hash = cookieHash(raw)
	var data string
	var expires int64
	err := s.conn.QueryRowContext(ctx, `SELECT subject, sid, identity, expires FROM appkit_sessions WHERE hash=?`, record.hash).Scan(&record.Subject, &record.sid, &data, &expires)
	if err != nil {
		return record, err
	}
	if json.Unmarshal([]byte(data), &record.Identity) != nil {
		return record, errors.New("identity: invalid session data")
	}
	record.expires = time.UnixMilli(expires)
	return record, nil
}

// watch cancels ctx when the credential whose hash is given ends, and returns
// what releases the watch once the request is served. Called with s.mu held.
func (s *Sessions) watch(hash string, cancel context.CancelFunc) (release func()) {
	watch := &sessionWatch{cancel: cancel}
	if s.watches[hash] == nil {
		s.watches[hash] = make(map[*sessionWatch]struct{})
	}
	s.watches[hash][watch] = struct{}{}
	return func() {
		cancel()
		s.mu.Lock()
		delete(s.watches[hash], watch)
		if len(s.watches[hash]) == 0 {
			delete(s.watches, hash)
		}
		s.mu.Unlock()
	}
}

func (s *Sessions) cancelSession(hash string) {
	for watch := range s.watches[hash] {
		watch.cancel()
	}
	delete(s.watches, hash)
}

func (s *Sessions) applyLogout(ctx context.Context, event logoutEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("identity: sessions closed")
	}
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO appkit_logouts VALUES(?,?,?,?,?)`, digest(event.TokenID), event.Subject, event.SessionID, event.IssuedAt.Unix(), time.Now().UnixMilli())
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return nil
	}
	where, args := "subject=?", []any{event.Subject}
	if event.SessionID != "" {
		where, args = "sid=?", []any{event.SessionID}
		if event.Subject != "" {
			where += " AND subject=?"
			args = append(args, event.Subject)
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT hash FROM appkit_sessions WHERE `+where, args...)
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var hash string
		if err = rows.Scan(&hash); err != nil {
			_ = rows.Close()
			return err
		}
		hashes = append(hashes, hash)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM appkit_sessions WHERE `+where, args...); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for _, hash := range hashes {
		s.cancelSession(hash)
	}
	return nil
}
