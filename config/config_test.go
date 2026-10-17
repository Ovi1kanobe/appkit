package config

import (
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
	want := "DATABASE_PATH,LISTEN_ADDRESS,APP_ENV,RAUTHY_ISSUER,RAUTHY_CLIENT_ID,RAUTHY_CLIENT_SECRET,APP_ORIGIN,SESSION_DATABASE,APP_MASTER_KEY,SMTP_HOST,SMTP_PORT"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("declared %s\nwant     %s", got, want)
	}
	first, host, port := declarations[0], declarations[9], declarations[10]
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
