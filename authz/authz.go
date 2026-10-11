// Package authz maps external groups to application-defined roles and permissions.
package authz

import (
	"fmt"
	"sort"
)

// Policy is immutable after construction and safe for concurrent use.
type Policy struct {
	roles  map[string][]string
	groups map[string][]string
}

// New validates and copies application role definitions and external group mappings.
func New(roles, groups map[string][]string) (*Policy, error) {
	policy := &Policy{roles: make(map[string][]string), groups: make(map[string][]string)}
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
	return policy, nil
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
