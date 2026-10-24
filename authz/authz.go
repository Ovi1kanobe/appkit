// Package authz maps external groups, the Rauthy clients of calling
// applications, and the personal keys people make, to application-defined
// roles and permissions.
package authz

import (
	"fmt"
	"sort"
)

// reservedPublicClientID is identity.PublicSubject, the subject a public
// write records, which no calling application may share. It is spelled out
// here because identity imports authz; identity's router test keeps the two
// in step.
const reservedPublicClientID = "public"

// Policy is immutable after construction and safe for concurrent use.
type Policy struct {
	roles     map[string][]string
	groups    map[string][]string
	clients   map[string][]string
	delegable map[string]struct{}
}

// New validates and copies the application's role definitions, the external
// groups that grant them to people, the Rauthy client IDs that grant them to
// calling applications, and the permissions a person may give a key. An
// application nobody calls passes nil clients; one that issues no keys passes
// nil delegable. A delegable permission must be one some role grants. The
// client ID "public" is refused, since it is reserved for anonymous public
// writes.
func New(roles, groups, clients map[string][]string, delegable []string) (*Policy, error) {
	policy := &Policy{roles: make(map[string][]string), groups: make(map[string][]string), clients: make(map[string][]string), delegable: make(map[string]struct{})}
	for role, permissions := range roles {
		if role == "" {
			return nil, fmt.Errorf("authz: empty role")
		}
		for _, permission := range permissions {
			if permission == "" {
				return nil, fmt.Errorf("authz: empty permission for role %q", role)
			}
		}
		policy.roles[role] = append([]string(nil), permissions...)
	}
	for group, mapped := range groups {
		if group == "" {
			return nil, fmt.Errorf("authz: empty group")
		}
		for _, role := range mapped {
			if _, exists := policy.roles[role]; !exists {
				return nil, fmt.Errorf("authz: unknown role %q", role)
			}
		}
		policy.groups[group] = append([]string(nil), mapped...)
	}
	for client, mapped := range clients {
		if client == "" {
			return nil, fmt.Errorf("authz: empty client")
		}
		if client == reservedPublicClientID {
			return nil, fmt.Errorf("authz: client ID %q is reserved for anonymous public writes; give the calling application another client ID in Rauthy", client)
		}
		for _, role := range mapped {
			if _, exists := policy.roles[role]; !exists {
				return nil, fmt.Errorf("authz: unknown role %q", role)
			}
		}
		policy.clients[client] = append([]string(nil), mapped...)
	}
	granted := make(map[string]struct{})
	for _, permissions := range policy.roles {
		for _, permission := range permissions {
			granted[permission] = struct{}{}
		}
	}
	for _, permission := range delegable {
		if _, exists := granted[permission]; !exists {
			return nil, fmt.Errorf("authz: delegable permission %q is granted by no role", permission)
		}
		if _, exists := policy.delegable[permission]; exists {
			return nil, fmt.Errorf("authz: duplicate delegable permission %q", permission)
		}
		policy.delegable[permission] = struct{}{}
	}
	return policy, nil
}

// Delegable returns the permissions a key may carry, sorted.
func (policy *Policy) Delegable() []string {
	permissions := make([]string, 0, len(policy.delegable))
	for permission := range policy.delegable {
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	return permissions
}

// Actor is a permission snapshot. Its zero value grants nothing.
type Actor struct {
	roles       []string
	permissions map[string]struct{}
}

// Resolve ignores unmapped groups. Identity.Roles are deliberately not trusted as
// application roles. Additional local role assignments must come from trusted code.
func (policy *Policy) Resolve(groups []string, localRoles ...string) Actor {
	roles := make(map[string]struct{})
	for _, group := range groups {
		for _, role := range policy.groups[group] {
			roles[role] = struct{}{}
		}
	}
	for _, role := range localRoles {
		if _, exists := policy.roles[role]; exists {
			roles[role] = struct{}{}
		}
	}
	return policy.actor(roles)
}

// ResolveClient returns what a calling application, named by its Rauthy client
// ID, may do. An unlisted client gets nothing.
func (policy *Policy) ResolveClient(clientID string) Actor {
	roles := make(map[string]struct{})
	for _, role := range policy.clients[clientID] {
		roles[role] = struct{}{}
	}
	return policy.actor(roles)
}

// ResolveKey returns what a key may do: the scopes it was given that are
// delegable and that the policy grants to its holder's groups. Roles are the
// holder's, as Resolve gives them; a key with no permission left gets nothing.
func (policy *Policy) ResolveKey(groups, scopes []string) Actor {
	holder := policy.Resolve(groups)
	actor := Actor{roles: holder.roles, permissions: make(map[string]struct{})}
	for _, scope := range scopes {
		if _, delegable := policy.delegable[scope]; delegable && holder.Can(scope) {
			actor.permissions[scope] = struct{}{}
		}
	}
	return actor
}

func (policy *Policy) actor(roles map[string]struct{}) Actor {
	actor := Actor{permissions: make(map[string]struct{})}
	for role := range roles {
		actor.roles = append(actor.roles, role)
		for _, permission := range policy.roles[role] {
			actor.permissions[permission] = struct{}{}
		}
	}
	sort.Strings(actor.roles)
	return actor
}

func (actor Actor) Can(permission string) bool {
	_, allowed := actor.permissions[permission]
	return allowed
}
func (actor Actor) Roles() []string { return append([]string(nil), actor.roles...) }
func (actor Actor) Permissions() []string {
	permissions := make([]string, 0, len(actor.permissions))
	for permission := range actor.permissions {
		permissions = append(permissions, permission)
	}
	sort.Strings(permissions)
	return permissions
}
