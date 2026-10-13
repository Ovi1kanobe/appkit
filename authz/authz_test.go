package authz

import (
	"reflect"
	"strings"
	"testing"
)

func TestPolicy(t *testing.T) {
	roles := map[string][]string{"reader": {"bots.read"}, "operator": {"bots.read", "bots.start"}}
	groups := map[string][]string{"viewers": {"reader"}, "operators": {"operator"}}
	clients := map[string][]string{"monitor": {"reader"}}
	policy, err := New(roles, groups, clients)
	if err != nil {
		t.Fatal(err)
	}
	roles["reader"][0] = "changed"
	groups["viewers"][0] = "unknown"
	clients["monitor"][0] = "unknown"
	for _, test := range []struct {
		name               string
		groups             []string
		roles, permissions []string
	}{
		{"one role", []string{"viewers"}, []string{"reader"}, []string{"bots.read"}},
		{"multiple roles", []string{"operators", "viewers", "operators"}, []string{"operator", "reader"}, []string{"bots.read", "bots.start"}},
		{"unmapped", []string{"unknown"}, nil, []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			actor := policy.Resolve(test.groups)
			if !reflect.DeepEqual(actor.Roles(), test.roles) || !reflect.DeepEqual(actor.Permissions(), test.permissions) {
				t.Fatalf("unexpected roles/permissions: %v %v", actor.Roles(), actor.Permissions())
			}
			if actor.Can("bots.delete") {
				t.Fatal("unknown permission allowed")
			}
			for _, permission := range test.permissions {
				if !actor.Can(permission) {
					t.Fatal("permission denied")
				}
			}
		})
	}
	if !policy.Resolve(nil, "operator").Can("bots.start") {
		t.Fatal("trusted local role ignored")
	}
	if policy.Resolve(nil, "unknown").Can("bots.read") {
		t.Fatal("unknown role allowed")
	}
	if (Actor{}).Can("anything") {
		t.Fatal("zero actor allowed")
	}
	if client := policy.ResolveClient("monitor"); !client.Can("bots.read") || client.Can("bots.start") || strings.Join(client.Roles(), ",") != "reader" {
		t.Fatalf("client permissions %v %v", client.Roles(), client.Permissions())
	}
	if policy.ResolveClient("stranger").Can("bots.read") || policy.ResolveClient("viewers").Can("bots.read") {
		t.Fatal("unlisted client allowed")
	}
}

func TestInvalidPolicy(t *testing.T) {
	for _, test := range []struct{ roles, groups, clients map[string][]string }{
		{map[string][]string{"": {}}, nil, nil},
		{map[string][]string{"role": {""}}, nil, nil},
		{nil, map[string][]string{"group": {"unknown"}}, nil},
		{nil, map[string][]string{"": {}}, nil},
		{nil, nil, map[string][]string{"client": {"unknown"}}},
		{nil, nil, map[string][]string{"": {}}},
	} {
		if _, err := New(test.roles, test.groups, test.clients); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}
