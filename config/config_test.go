package config

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeclarationsListEveryVariableInOrder(t *testing.T) {
	environment := New()
	environment.AppKit(Defaults{})
	environment.Required("SMTP_HOST", "mail server")
	environment.Optional("SMTP_PORT", "587", "mail port")

	declarations := environment.Declarations()
	var names []string
	for _, declaration := range declarations {
		names = append(names, declaration.Name)
	}
	want := "DATABASE_PATH,LISTEN_ADDRESS,APP_ENV,RAUTHY_ISSUER,RAUTHY_CLIENT_ID,RAUTHY_CLIENT_SECRET,APP_ORIGIN,SESSION_DATABASE,CLIENT_ADDRESS,APP_MASTER_KEY,SMTP_HOST,SMTP_PORT"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("declared %s\nwant     %s", got, want)
	}
	first, host, port := declarations[0], declarations[10], declarations[11]
	if first.Required || first.Default != "app.sqlite" || first.Description == "" {
		t.Errorf("optional declaration %+v", first)
	}
	if !host.Required || host.Description != "mail server" {
		t.Errorf("required declaration %+v", host)
	}
	if port.Required || port.Default != "587" {
		t.Errorf("optional declaration %+v", port)
	}
}

// TestClientAddress checks that CLIENT_ADDRESS accepts exactly remote and
// header:<Name>, that each reads the address it names, and that anything else
// or nothing fails at startup.
func TestClientAddress(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "192.0.2.1:4321"
	request.Header.Add("X-Forwarded-For", "198.51.100.1, 203.0.113.5")
	request.Header.Add("X-Forwarded-For", "203.0.113.7")
	request.Header.Set("CF-Connecting-IP", "203.0.113.9")
	for _, test := range []struct {
		value, address, problem string
	}{
		{"remote", "192.0.2.1", ""},
		{"header:X-Forwarded-For", "203.0.113.7", ""},
		{"header:x-forwarded-for", "203.0.113.7", ""},
		{"header:CF-Connecting-IP", "203.0.113.9", ""},
		{"header:X-Real-IP", "", ""},
		{"", "", "CLIENT_ADDRESS is not set"},
		{"Remote", "", `CLIENT_ADDRESS is invalid: must be remote, for the connection's address when nothing sits in front of the app, or header:<Name>`},
		{"header:", "", "CLIENT_ADDRESS is invalid"},
		{"header:X Forwarded For", "", "CLIENT_ADDRESS is invalid"},
		{"X-Forwarded-For", "", "CLIENT_ADDRESS is invalid"},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv("CLIENT_ADDRESS", test.value)
			environment := New()
			appKit := environment.AppKit(Defaults{})
			err := environment.Check()
			if test.problem == "" {
				if appKit.ClientAddress == nil || err != nil && strings.Contains(err.Error(), "CLIENT_ADDRESS") {
					t.Fatalf("CLIENT_ADDRESS=%q refused: %v", test.value, err)
				}
				if got := appKit.ClientAddress(request); got != test.address {
					t.Fatalf("address %q, want %q", got, test.address)
				}
				return
			}
			if appKit.ClientAddress != nil || err == nil || !strings.Contains(err.Error(), test.problem) {
				t.Fatalf("CLIENT_ADDRESS=%q: %v, want %q", test.value, err, test.problem)
			}
		})
	}
}
