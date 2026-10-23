// Package identity authenticates actors using Rauthy as an OpenID Connect provider.
package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"time"
)

// Identity is the authenticated caller of a request: the provider's claims plus
// the permissions the application's policy grants, resolved once when the
// identity is attached. For a person, Subject is the provider's canonical OIDC
// sub, never an email address. For a calling application, Client is true and
// Subject is its Rauthy client ID. For a person's key, KeyID names the key
// and the permissions are the key's; it is empty for a session or a Rauthy
// token.
type Identity struct {
	Subject     string   `json:"subject"`
	Client      bool     `json:"client,omitempty"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	KeyID       string   `json:"key_id,omitempty"`
	Permissions []string `json:"-"` // resolved per request, never stored or sent as part of the identity
	expiresAt   time.Time
}

// Can reports whether the identity holds permission.
func (actor Identity) Can(permission string) bool {
	return slices.Contains(actor.Permissions, permission)
}

type contextKey struct{}

// WithContext attaches an already authenticated identity. It does not authenticate.
func WithContext(ctx context.Context, actor Identity) context.Context {
	actor.Groups = append([]string(nil), actor.Groups...)
	actor.Roles = append([]string(nil), actor.Roles...)
	actor.Permissions = append([]string(nil), actor.Permissions...)
	return context.WithValue(ctx, contextKey{}, actor)
}

// FromContext returns the identity a private or service route attached, and
// whether there is one. It panics on a public route's request, because a
// public handler serves everyone the same and must never read who is asking.
func FromContext(ctx context.Context) (Identity, bool) {
	if ctx.Value(publicContextKey{}) != nil {
		panic("identity: a public route's handler read the identity; public handlers serve everyone the same")
	}
	actor, ok := ctx.Value(contextKey{}).(Identity)
	actor.Groups = append([]string(nil), actor.Groups...)
	actor.Roles = append([]string(nil), actor.Roles...)
	actor.Permissions = append([]string(nil), actor.Permissions...)
	return actor, ok && actor.Subject != ""
}

// requirePermission passes a request on only when its authenticated identity
// holds permission: 401 without an identity, 403 without the permission.
// The Router puts it inside require or bearer, which attach the permissions.
func requirePermission(permission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		person, ok := FromContext(request.Context())
		if !ok {
			writeError(writer, http.StatusUnauthorized, "Sign in required.")
			return
		}
		if !person.Can(permission) {
			writeError(writer, http.StatusForbidden, "You don't have permission for this.")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// writeError answers API and WebSocket requests with {"error": message}, the
// shape applications use, so pages read every error the same way.
func writeError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": message})
}
