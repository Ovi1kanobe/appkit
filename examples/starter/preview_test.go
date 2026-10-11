//go:build preview

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"

	"github.com/Ovi1kanobe/appkit/frontend"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
	"github.com/Ovi1kanobe/appkit/schema"

	"github.com/Ovi1kanobe/appkit/examples/starter/systems/userprofiles"
)

// TestPreview serves the built frontend with the real routes and a fake Rauthy,
// so the app can be used in a browser before a Rauthy client exists. It runs
// only through make preview, prints a session cookie per group, and serves
// until interrupted. Mirror main_test.go here as systems and routes are added,
// and seed whatever data a page needs after the systems open.
func TestPreview(t *testing.T) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	address := os.Getenv("PREVIEW_ADDRESS")
	if address == "" {
		address = "127.0.0.1:8090"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://" + listener.Addr().String()
	provider := identitytest.NewProvider(t)
	policy, err := newPolicy()
	if err != nil {
		t.Fatal(err)
	}
	database, err := schema.Open(ctx, filepath.Join(t.TempDir(), "preview.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profiles, err := userprofiles.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := identity.NewSessions(ctx, identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: origin,
		DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy, AppInfo: recordProfile(profiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	pages, err := frontend.New(os.DirFS("frontend/dist"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: routes(sessions, pages)}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	fmt.Printf("\nPreview at %s. Set one cookie for %s in the browser, then open the page:\n", origin, listener.Addr().String())
	for _, person := range []identitytest.User{
		{Subject: "member", Email: "member@example.test", Groups: []string{membersGroup}},
	} {
		cookie := provider.SignIn(t, origin, person)
		fmt.Printf("  %-12s %s=%s\n", person.Subject, cookie.Name, cookie.Value)
	}
	fmt.Println("Ctrl+C stops the preview.")
	<-ctx.Done()
}
