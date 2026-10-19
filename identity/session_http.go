package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Routes mounts the complete /auth/ namespace, including login, callback,
// logout, back-channel logout, session JSON, session-end events, and key
// management.
func (s *Sessions) Routes(mux *http.ServeMux) {
	auth := http.NewServeMux()
	auth.HandleFunc("GET /auth/login", s.login)
	auth.HandleFunc("GET /auth/callback", s.callback)
	auth.HandleFunc("POST /auth/logout", s.logout)
	auth.Handle("POST /auth/backchannel", s.verifier.logoutHandler(s.applyLogout))
	auth.Handle("GET /auth/session", s.Optional(http.HandlerFunc(s.sessionJSON)))
	auth.Handle("GET /auth/events", s.Optional(http.HandlerFunc(s.events)))
	s.keyRoutes(auth)
	mux.Handle("/auth/", s.boundary(auth))
}

// Bearer authenticates a separate non-browser route with an access token and
// attaches the identity with its permissions: a person's from their groups, a
// calling application's from the policy's client list. It ignores browser
// cookies and refuses a personal key; logout does not revoke an already
// issued access token.
func (s *Sessions) Bearer(next http.Handler) http.Handler {
	return s.verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, _ := FromContext(r.Context())
		if caller.Client {
			caller.Permissions = s.config.Policy.ResolveClient(caller.Subject).Permissions()
		} else {
			caller.Permissions = s.config.Policy.Resolve(caller.Groups).Permissions()
		}
		next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), caller)))
	}))
}

func (s *Sessions) boundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if s.origin.Scheme == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.EqualFold(r.Host, s.origin.Host) {
			message := "This application is served at " + s.config.Origin
			if strings.HasPrefix(r.URL.Path, "/api/") || r.Header.Get("Upgrade") != "" {
				writeError(w, http.StatusMisdirectedRequest, message)
			} else {
				http.Error(w, message, http.StatusMisdirectedRequest)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Sessions) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 0 {
		return len(origins) == 1 && origins[0] == s.config.Origin
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

func (s *Sessions) csrfOK(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return r.Header.Get("Origin") == s.config.Origin && s.sameOrigin(r)
	}
	switch r.Method {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return s.sameOrigin(r)
}

// Optional attaches a browser identity if a live session exists, and protects
// mutations and WebSocket upgrades against cross-origin use. A request with a
// Bearer header presents a personal key instead and is never anonymous: it is
// served as the key's holder or refused with 401, and never falls back to the
// cookie. The request context ends when its session or key expires or is
// revoked. Handlers must respect that context.
func (s *Sessions) Optional(next http.Handler) http.Handler {
	return s.boundary(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isKeyRequest(r) {
			s.admitKey(w, r, next)
			return
		}
		if !s.csrfOK(r) {
			writeError(w, http.StatusForbidden, "Same-origin request required.")
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			writeError(w, http.StatusServiceUnavailable, "Sign-in is unavailable.")
			return
		}
		record, err := s.readSession(r.Context(), s.cookie(r, s.cookieName))
		if errors.Is(err, sql.ErrNoRows) || err == nil && !time.Now().Before(record.expires) {
			s.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}
		if err != nil {
			s.mu.Unlock()
			writeError(w, http.StatusServiceUnavailable, "Sign-in is unavailable.")
			return
		}
		person := record.Identity
		person.Permissions = s.config.Policy.Resolve(person.Groups).Permissions()
		ctx, cancel := context.WithDeadline(WithContext(r.Context(), person), record.expires)
		release := s.watch(record.hash, cancel)
		s.mu.Unlock()
		defer release()
		next.ServeHTTP(w, r.WithContext(ctx))
	}))
}

// Require redirects anonymous page requests to sign-in. API and WebSocket
// requests receive 401. Resource permissions remain the application's decision.
func (s *Sessions) Require(next http.Handler) http.Handler {
	return s.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); !ok {
			if r.Method == "GET" && strings.Contains(r.Header.Get("Accept"), "text/html") && r.Header.Get("Upgrade") == "" {
				http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			} else {
				writeError(w, http.StatusUnauthorized, "Sign in required.")
			}
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Sessions) cookie(r *http.Request, name string) string {
	values := r.CookiesNamed(name)
	if len(values) != 1 {
		return ""
	}
	return values[0].Value
}
func (s *Sessions) setCookie(w http.ResponseWriter, name, value string, until time.Time) {
	maxAge := int(time.Until(until).Seconds())
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: s.origin.Scheme == "https", SameSite: http.SameSiteLaxMode, Expires: until, MaxAge: maxAge})
}
func (s *Sessions) oauth() oauth2.Config {
	endpoint := s.verifier.provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return oauth2.Config{ClientID: s.config.ClientID, ClientSecret: s.config.ClientSecret, Endpoint: endpoint, RedirectURL: s.config.Origin + "/auth/callback", Scopes: []string{"openid", "email", "groups"}}
}
func localNext(value string) string {
	u, err := url.Parse(value)
	if err != nil || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\\r\n") || u.IsAbs() || u.Host != "" || strings.HasPrefix(u.Path, "/auth/") {
		return "/"
	}
	return value
}

func (s *Sessions) login(w http.ResponseWriter, r *http.Request) {
	state, browser, nonce, pkce := randomSecret(), randomSecret(), randomSecret(), randomSecret()
	now := time.Now()
	s.mu.Lock()
	for key, flow := range s.flows {
		if now.Sub(flow.started) > 5*time.Minute {
			delete(s.flows, key)
		}
	}
	if s.closed || len(s.flows) >= 4096 {
		s.mu.Unlock()
		http.Error(w, "sign-in temporarily unavailable", 503)
		return
	}
	s.flows[digest(state)] = loginFlow{browser: digest(browser), nonce: nonce, verifier: pkce, next: localNext(r.URL.Query().Get("next")), started: now}
	s.mu.Unlock()
	s.setCookie(w, s.cookieName+"_login", browser, now.Add(5*time.Minute))
	config := s.oauth()
	http.Redirect(w, r, config.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce), oauth2.S256ChallengeOption(pkce)), http.StatusSeeOther)
}

func (s *Sessions) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	s.mu.Lock()
	flow, ok := s.flows[digest(state)]
	if ok && flow.browser == digest(s.cookie(r, s.cookieName+"_login")) {
		delete(s.flows, digest(state))
	} else {
		ok = false
	}
	s.mu.Unlock()
	s.setCookie(w, s.cookieName+"_login", "", time.Unix(1, 0))
	if !ok || len(q["state"]) != 1 || time.Since(flow.started) > 5*time.Minute || q.Get("error") != "" || len(q["code"]) != 1 || q.Get("code") == "" {
		http.Error(w, "sign-in failed or expired; please start again", 400)
		return
	}
	config := s.oauth()
	ctx := oidc.ClientContext(r.Context(), s.verifier.httpClient)
	token, err := config.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(flow.verifier))
	if err != nil {
		s.loginError(w, "code exchange failed")
		return
	}
	// Sessions never refresh: a refresh token, if Rauthy sends one, is discarded unused.
	rawID, ok := token.Extra("id_token").(string)
	if !ok || len(rawID) > 64*1024 {
		s.loginError(w, "missing ID token")
		return
	}
	id, err := s.verifier.tokenVerifier.Verify(ctx, rawID)
	if err != nil {
		s.loginError(w, "ID token verification failed")
		return
	}
	var claims struct {
		Email  string          `json:"email"`
		Groups []string        `json:"groups"`
		SID    string          `json:"sid"`
		AZP    string          `json:"azp"`
		NBF    int64           `json:"nbf"`
		Events json.RawMessage `json:"events"`
	}
	if id.Claims(&claims) != nil || id.Subject == "" || claims.SID == "" || id.Nonce != flow.nonce || id.Issuer != s.config.Issuer || id.IssuedAt.IsZero() || id.IssuedAt.After(time.Now().Add(clockSkew)) || claims.NBF > time.Now().Add(clockSkew).Unix() || claims.Events != nil || (claims.AZP != "" && claims.AZP != s.config.ClientID) || (len(id.Audience) > 1 && claims.AZP != s.config.ClientID) {
		s.loginError(w, "invalid ID token claims")
		return
	}
	if id.AccessTokenHash == "" || id.VerifyAccessToken(token.AccessToken) != nil {
		s.loginError(w, "access token binding failed")
		return
	}
	raw := randomSecret()
	record := sessionRecord{Identity: Identity{Subject: id.Subject, Email: claims.Email, Groups: claims.Groups}, hash: cookieHash(raw), sid: claims.SID, expires: time.Now().Add(s.config.Lifetime)}
	data, _ := json.Marshal(record.Identity)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		http.Error(w, "sessions unavailable", 503)
		return
	}
	// The person's keys learn their groups as of this sign-in, whether or not
	// a session follows: a person refused below keeps keys that now get nothing.
	if err = s.refreshKeys(ctx, record.Identity); err != nil {
		http.Error(w, "sessions unavailable", 503)
		return
	}
	// A person with none of this application's groups gets no session.
	if len(s.config.Policy.Resolve(claims.Groups).Roles()) == 0 {
		http.Error(w, "You don't have access to this application. Ask its administrator to add you to one of its groups, then sign in again.", http.StatusForbidden)
		return
	}
	// Callback flows expire after five minutes and provider calls after ten
	// seconds. Ten minutes of tombstones also covers the logout validator's age.
	_, err = s.conn.ExecContext(ctx, `DELETE FROM appkit_logouts WHERE received<?`, time.Now().Add(-10*time.Minute).UnixMilli())
	var count int
	if err == nil {
		err = s.conn.QueryRowContext(ctx, `SELECT count(*) FROM appkit_logouts WHERE (sid<>'' AND sid=? AND (subject='' OR subject=?)) OR (sid='' AND subject=? AND (received>=? OR issued>=?))`, record.sid, record.Subject, record.Subject, flow.started.UnixMilli(), id.IssuedAt.Unix()).Scan(&count)
	}
	if err != nil {
		http.Error(w, "sessions unavailable", 503)
		return
	}
	if count != 0 {
		http.Error(w, "sign-in was ended by Rauthy; please sign in again", 401)
		return
	}
	_, err = s.conn.ExecContext(ctx, `INSERT INTO appkit_sessions(hash,subject,sid,identity,expires) VALUES(?,?,?,?,?)`, record.hash, record.Subject, record.sid, string(data), record.expires.UnixMilli())
	if err != nil {
		http.Error(w, "sessions unavailable", 503)
		return
	}
	// A new login replaces this browser's previous app session.
	old := cookieHash(s.cookie(r, s.cookieName))
	if _, err = s.conn.ExecContext(ctx, `DELETE FROM appkit_sessions WHERE hash=? OR expires<?`, old, time.Now().UnixMilli()); err != nil {
		http.Error(w, "sessions unavailable", 503)
		return
	}
	s.cancelSession(old)
	s.setCookie(w, s.cookieName, raw, record.expires)
	http.Redirect(w, r, flow.next, http.StatusSeeOther)
}

func (s *Sessions) loginError(w http.ResponseWriter, reason string) {
	// Only static, AppKit-owned explanations: never provider errors or claims.
	slog.Warn("AppKit sign-in failed", "reason", reason)
	http.Error(w, "Sign-in is unavailable: "+reason+". Contact the application administrator.", http.StatusBadGateway)
}

// logout ends only this app session. Rauthy's own session is untouched; Rauthy
// reports its logouts through back-channel logout.
func (s *Sessions) logout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "same-origin request required", 403)
		return
	}
	hash := cookieHash(s.cookie(r, s.cookieName))
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		http.Error(w, "sessions unavailable", 503)
		return
	}
	_, err := s.conn.ExecContext(r.Context(), `DELETE FROM appkit_sessions WHERE hash=?`, hash)
	if err == nil {
		s.cancelSession(hash)
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, "logout unavailable", 503)
		return
	}
	s.setCookie(w, s.cookieName, "", time.Unix(1, 0))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sessionJSON answers who is signed in and what they may do. A browser also
// learns what it may give a key, when the app issues keys and the person holds
// something delegable; a key learns about itself, and OnSessionRequest does
// not run for it.
func (s *Sessions) sessionJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	actor, ok := FromContext(r.Context())
	if !ok {
		_, _ = io.WriteString(w, `{"user":null,"permissions":[]}`)
		return
	}
	if record, isKey := keyFromContext(r.Context()); isKey {
		_ = json.NewEncoder(w).Encode(struct {
			User        Identity `json:"user"`
			Permissions []string `json:"permissions"`
			Key         any      `json:"key"`
		}{actor, actor.Permissions, map[string]any{"name": record.name, "scopes": record.scopes, "expires_at": record.expires.UTC()}})
		return
	}
	var app any
	if s.config.OnSessionRequest != nil {
		info, err := s.config.OnSessionRequest(r, actor)
		if err != nil {
			http.Error(w, "session unavailable", 503)
			return
		}
		app = info
	}
	var keys any
	if delegable := s.delegableFor(actor); len(delegable) != 0 {
		keys = map[string]any{"delegable": delegable, "max_lifetime_seconds": int64(s.config.KeyLifetime / time.Second)}
	}
	_ = json.NewEncoder(w).Encode(struct {
		User        Identity `json:"user"`
		Permissions []string `json:"permissions"`
		App         any      `json:"app,omitempty"`
		Keys        any      `json:"keys,omitempty"`
	}{actor, actor.Permissions, app, keys})
}

func (s *Sessions) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(w)
	send := func(event string) error {
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(w, "event: %s\ndata: {}\n\n", event); err != nil {
			return err
		}
		return controller.Flush()
	}
	if _, ok := FromContext(r.Context()); !ok {
		_ = send("signed-out")
		return
	}
	if send("ready") != nil {
		return
	}
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			_ = send("signed-out")
			return
		case <-ticker.C:
			if send("ready") != nil {
				return
			}
		}
	}
}
