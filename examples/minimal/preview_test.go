//go:build preview

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"

	"github.com/Ovi1kanobe/appkit/encryption"
	"github.com/Ovi1kanobe/appkit/frontend"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/identity/identitytest"
	"github.com/Ovi1kanobe/appkit/realtime"
	"github.com/Ovi1kanobe/appkit/schema"

	wsapi "github.com/Ovi1kanobe/appkit/examples/minimal/api/websocket"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/userprofiles"
)

// TestPreview serves the built frontend with the real routes and a fake Rauthy,
// so the app can be used in a browser before a Rauthy client exists. It runs
// only through make preview, prints a session cookie per group, and serves
// until interrupted. It mirrors main.go's run and main_test.go.
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
	hub := &realtime.Hub{}
	defer hub.Close()
	notesPublisher := wsapi.NewNotesPublisher(hub, profiles)
	noteSystem, err := notes.Open(ctx, database, notesPublisher.Add)
	if err != nil {
		t.Fatal(err)
	}
	masterKey, err := encryption.ParseKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	emailPublisher := wsapi.NewEmailPublisher(hub)
	emailSystem, err := email.Open(ctx, database, masterKey, emailPublisher.Add)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticSystem := diagnostics.New()
	go notesPublisher.Run(ctx)
	go emailPublisher.Run(ctx)
	go wsapi.PublishStatus(ctx, hub, diagnosticSystem)
	sessions, err := identity.NewSessions(ctx, identity.SessionConfig{
		Issuer: provider.Issuer, ClientID: provider.ClientID, Origin: origin,
		DatabasePath: filepath.Join(t.TempDir(), "sessions.sqlite"), Policy: policy, OnSessionRequest: recordProfile(profiles),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	pages, err := frontend.New(os.DirFS("frontend/dist"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: routes(sessions, profiles, diagnosticSystem, noteSystem, emailSystem, hub, pages)}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	fmt.Printf("\nPreview at %s. Set one cookie for %s in the browser, then open the page:\n", origin, listener.Addr().String())
	for _, person := range []identitytest.User{
		{Subject: "member", Email: "member@example.test", Groups: []string{memberGroup}},
		{Subject: "admin", Email: "admin@example.test", Groups: []string{memberGroup, adminGroup}},
	} {
		cookie := provider.SignIn(t, origin, person)
		fmt.Printf("  %-12s %s=%s\n", person.Subject, cookie.Name, cookie.Value)
	}
	fmt.Println("Ctrl+C stops the preview.")
	<-ctx.Done()
}
