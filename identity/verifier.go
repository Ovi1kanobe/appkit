package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var errInvalidToken = errors.New("identity: invalid token")

// clockSkew tolerates small clock differences with Rauthy for iat and nbf.
const clockSkew = 30 * time.Second

type Config struct {
	Issuer   string
	ClientID string
	// httpClient lets package tests trust a local TLS provider fixture.
	httpClient *http.Client
}

// Verifier is reusable and caches provider signing keys. It owns no application session.
type Verifier struct {
	provider            *oidc.Provider
	httpClient          *http.Client
	tokenVerifier       *oidc.IDTokenVerifier
	logoutTokenVerifier *oidc.IDTokenVerifier
	expectedIssuer      string
}

func New(ctx context.Context, config Config) (*Verifier, error) {
	issuerURL, err := url.Parse(config.Issuer)
	if err != nil || !secureURL(issuerURL) || issuerURL.RawQuery != "" || strings.TrimSpace(config.ClientID) == "" {
		return nil, errors.New("identity: invalid issuer or client ID")
	}
	providerHTTPClient := config.httpClient
	if providerHTTPClient == nil {
		providerHTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	client := *providerHTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("identity: provider redirect refused") }
	providerHTTPClient = &client
	providerRequestContext := oidc.ClientContext(ctx, providerHTTPClient)
	provider, err := oidc.NewProvider(providerRequestContext, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("identity: provider discovery failed: %w", err)
	}
	var discoveryDocument struct {
		SigningKeysURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&discoveryDocument); err != nil {
		return nil, errors.New("identity: invalid discovery metadata")
	}
	signingKeysURL, err := url.Parse(discoveryDocument.SigningKeysURL)
	if err != nil || !secureURL(signingKeysURL) {
		return nil, errors.New("identity: invalid JWKS endpoint")
	}
	return &Verifier{
		provider: provider, httpClient: providerHTTPClient,
		tokenVerifier: provider.VerifierContext(providerRequestContext, &oidc.Config{ClientID: config.ClientID}),
		// OIDC logout exp is optional. Verify signatures/issuer/audience with the
		// library, then enforce logout-specific timestamps and claims below.
		logoutTokenVerifier: provider.VerifierContext(providerRequestContext, &oidc.Config{ClientID: config.ClientID, SkipExpiryCheck: true}),
		expectedIssuer:      config.Issuer,
	}, nil
}

// authenticate accepts an RFC 9068 access token (protected header typ=at+jwt),
// as issued by Rauthy 0.37 and later, for a person or, through the client
// credentials grant, for a calling application. Rauthy omits sub from a client
// token and names the client in azp.
// ID tokens, refresh tokens, and logout tokens are not API bearer credentials.
func (verifier *Verifier) authenticate(ctx context.Context, rawToken string) (Identity, error) {
	if len(rawToken) == 0 || len(rawToken) > 64*1024 {
		return Identity{}, errInvalidToken
	}
	encodedHeader, _, found := strings.Cut(rawToken, ".")
	if !found {
		return Identity{}, errInvalidToken
	}
	decodedHeader, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	var tokenHeader struct {
		Type string `json:"typ"`
	}
	if err != nil || json.Unmarshal(decodedHeader, &tokenHeader) != nil || !strings.EqualFold(tokenHeader.Type, "at+jwt") {
		return Identity{}, errInvalidToken
	}
	// The library checks the signature, issuer, audience, and expiry.
	verifiedToken, err := verifier.tokenVerifier.Verify(ctx, rawToken)
	if err != nil {
		return Identity{}, errInvalidToken
	}
	var extraClaims struct {
		Email           string          `json:"email"`
		Groups          []string        `json:"groups"`
		Roles           []string        `json:"roles"`
		AuthorizedParty string          `json:"azp"`
		NotBefore       int64           `json:"nbf"`
		Events          json.RawMessage `json:"events"`
	}
	if verifiedToken.Claims(&extraClaims) != nil || verifiedToken.Issuer != verifier.expectedIssuer || extraClaims.Events != nil {
		return Identity{}, errInvalidToken
	}
	now := time.Now()
	if verifiedToken.IssuedAt.IsZero() || verifiedToken.IssuedAt.After(now.Add(clockSkew)) || extraClaims.NotBefore > now.Add(clockSkew).Unix() {
		return Identity{}, errInvalidToken
	}
	if verifiedToken.Subject != "" {
		return Identity{Subject: verifiedToken.Subject, Email: extraClaims.Email, Groups: extraClaims.Groups, Roles: extraClaims.Roles, expiresAt: verifiedToken.Expiry}, nil
	}
	// A client token names no person: it carries neither groups nor an email,
	// and its permissions come from the policy's client list, never from claims.
	if extraClaims.AuthorizedParty == "" || extraClaims.Email != "" || len(extraClaims.Groups) != 0 || len(extraClaims.Roles) != 0 {
		return Identity{}, errInvalidToken
	}
	return Identity{Subject: extraClaims.AuthorizedParty, Client: true, expiresAt: verifiedToken.Expiry}, nil
}

// authenticateRequest is usable before an HTTP or WebSocket handler.
// Tokens in URLs or cookies are deliberately not accepted by this bearer API.
func (verifier *Verifier) authenticateRequest(request *http.Request) (Identity, error) {
	authorizationHeaders := request.Header.Values("Authorization")
	if len(authorizationHeaders) == 0 {
		return Identity{}, errInvalidToken
	}
	if len(authorizationHeaders) != 1 {
		return Identity{}, errInvalidToken
	}
	authorizationFields := strings.Fields(authorizationHeaders[0])
	if len(authorizationFields) == 0 {
		return Identity{}, errInvalidToken
	}
	if !strings.EqualFold(authorizationFields[0], "Bearer") {
		return Identity{}, errInvalidToken
	}
	if len(authorizationFields) != 2 {
		return Identity{}, errInvalidToken
	}
	return verifier.authenticate(request.Context(), authorizationFields[1])
}

func (verifier *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		actor, err := verifier.authenticateRequest(request)
		if err != nil {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			writeError(writer, http.StatusUnauthorized, "Sign in required.")
			return
		}
		ctx, cancel := context.WithDeadline(WithContext(request.Context(), actor), actor.expiresAt)
		defer cancel()
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

const logoutEventType = "http://schemas.openid.net/event/backchannel-logout"

type logoutEvent struct {
	Subject   string
	SessionID string
	TokenID   string
	IssuedAt  time.Time
}

// validateLogout validates an OIDC back-channel logout JWT, including a five-minute
// maximum age and 30-second future clock tolerance. The caller must deduplicate
// TokenID atomically with session invalidation for at least six minutes.
func (verifier *Verifier) validateLogout(ctx context.Context, rawToken string) (logoutEvent, error) {
	if len(rawToken) == 0 || len(rawToken) > 64*1024 {
		return logoutEvent{}, errInvalidToken
	}
	verifiedToken, err := verifier.logoutTokenVerifier.Verify(ctx, rawToken)
	if err != nil {
		return logoutEvent{}, errInvalidToken
	}
	var logoutClaims struct {
		SessionID string                     `json:"sid"`
		TokenID   string                     `json:"jti"`
		Nonce     json.RawMessage            `json:"nonce"`
		Expiry    *int64                     `json:"exp"`
		NotBefore int64                      `json:"nbf"`
		Events    map[string]json.RawMessage `json:"events"`
	}
	now := time.Now()
	if verifiedToken.Claims(&logoutClaims) != nil || verifiedToken.Issuer != verifier.expectedIssuer || logoutClaims.TokenID == "" || logoutClaims.Nonce != nil {
		return logoutEvent{}, errInvalidToken
	}
	if verifiedToken.Subject == "" && logoutClaims.SessionID == "" {
		return logoutEvent{}, errInvalidToken
	}
	if verifiedToken.IssuedAt.IsZero() || verifiedToken.IssuedAt.Before(now.Add(-5*time.Minute)) || verifiedToken.IssuedAt.After(now.Add(clockSkew)) {
		return logoutEvent{}, errInvalidToken
	}
	if (logoutClaims.Expiry != nil && *logoutClaims.Expiry <= now.Unix()) || logoutClaims.NotBefore > now.Add(clockSkew).Unix() {
		return logoutEvent{}, errInvalidToken
	}
	var logoutEventClaims map[string]json.RawMessage
	if json.Unmarshal(logoutClaims.Events[logoutEventType], &logoutEventClaims) != nil || logoutEventClaims == nil || len(logoutEventClaims) != 0 {
		return logoutEvent{}, errInvalidToken
	}
	return logoutEvent{Subject: verifiedToken.Subject, SessionID: logoutClaims.SessionID, TokenID: logoutClaims.TokenID, IssuedAt: verifiedToken.IssuedAt}, nil
}

// logoutHandler parses an OIDC POST and invokes application-owned, idempotent
// session invalidation. processLogout must enforce replay protection and persist any
// needed revocation before returning nil. It must not log the incoming token.
func (verifier *Verifier) logoutHandler(processLogout func(context.Context, logoutEvent) error) http.Handler {
	if processLogout == nil {
		panic("identity: nil logout processor")
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", "POST")
			http.Error(writer, "method not allowed", 405)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, 96*1024)
		if request.ParseForm() != nil || len(request.PostForm["logout_token"]) != 1 {
			http.Error(writer, "invalid logout request", 400)
			return
		}
		event, err := verifier.validateLogout(request.Context(), request.PostForm.Get("logout_token"))
		if err != nil {
			http.Error(writer, "invalid logout token", 400)
			return
		}
		if err := processLogout(request.Context(), event); err != nil {
			http.Error(writer, "logout unavailable", 503)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
}
