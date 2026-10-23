// The application is the composition root. AppKit never starts it.
package main

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/config"
	"github.com/Ovi1kanobe/appkit/examples/minimal/api/access"
	httpapi "github.com/Ovi1kanobe/appkit/examples/minimal/api/http"
	wsapi "github.com/Ovi1kanobe/appkit/examples/minimal/api/websocket"
	"github.com/Ovi1kanobe/appkit/examples/minimal/cli"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/diagnostics"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/email"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/notes"
	"github.com/Ovi1kanobe/appkit/examples/minimal/systems/userprofiles"
	"github.com/Ovi1kanobe/appkit/frontend"
	"github.com/Ovi1kanobe/appkit/identity"
	"github.com/Ovi1kanobe/appkit/realtime"
	"github.com/Ovi1kanobe/appkit/schema"
)

// The frontend build output; make builds it before any Go command.
//
//go:embed frontend/dist
var frontendFiles embed.FS

func main() {
	os.Exit(cli.Run(os.Args[1:], serve, func(environment *config.Environment) { configure(environment) }))
}

// configure declares every variable the application reads. serve checks and
// uses the values; install asks the operator for each one.
func configure(environment *config.Environment) config.AppKit {
	// AppKit declares its own variables; add the application's below with
	// environment.Required or environment.Optional.
	return environment.AppKit(config.Defaults{})
}

// serve reads the configuration and runs the server until it stops.
func serve() error {
	environment := config.New()
	appKit := configure(environment)
	if err := environment.Check(); err != nil {
		return err
	}
	return run(appKit)
}

// The Rauthy groups that grant this application's roles. Every group name
// starts with the application name, because Rauthy groups are shared by all apps.
const (
	memberGroup = "example-members"
	adminGroup  = "example-admins"
)

// The Rauthy client of another application that calls this one, by its client
// ID. Its token is accepted only when Rauthy lists this application's client
// ID under that client's allowed resources.
const monitorClient = "monitor"

// newPolicy defines the application's roles and permissions: what each group
// grants a person, what each client grants a calling application, and which
// permissions a person may give a key they make for a tool.
func newPolicy() (*authz.Policy, error) {
	return authz.New(
		map[string][]string{
			"member":  {access.DiagnosticsRead, access.NotesRead, access.NotesWrite},
			"admin":   {access.EmailWrite},
			"monitor": {access.DiagnosticsRead},
		},
		map[string][]string{memberGroup: {"member"}, adminGroup: {"admin"}},
		map[string][]string{monitorClient: {"monitor"}},
		[]string{access.NotesRead},
	)
}

func run(appKit config.AppKit) error {
	app, sessionConfig, masterKey := appKit.App, appKit.Sessions, appKit.MasterKey
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	development := app.Development()
	policy, err := newPolicy()
	if err != nil {
		return err
	}
	database, err := schema.Open(ctx, app.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	profiles, err := userprofiles.Open(ctx, database)
	if err != nil {
		return err
	}
	hub := &realtime.Hub{}
	defer hub.Close()
	notesPublisher := wsapi.NewNotesPublisher(hub, profiles)
	noteSystem, err := notes.Open(ctx, database, notesPublisher.Add)
	if err != nil {
		return err
	}
	emailPublisher := wsapi.NewEmailPublisher(hub)
	emailSystem, err := email.Open(ctx, database, masterKey, emailPublisher.Add)
	if err != nil {
		return err
	}
	diagnosticSystem := diagnostics.New()
	files, err := fs.Sub(frontendFiles, "frontend/dist")
	if err != nil {
		return err
	}
	if development {
		files = os.DirFS("frontend/dist") // make dev rebuilds it on save; refresh the browser
	}
	pages, err := frontend.New(files, frontend.Config{HashedAssets: "assets"})
	if err != nil {
		return err
	}
	sessionConfig.Policy = policy
	sessionConfig.OnSessionRequest = recordProfile(profiles)
	sessions, err := identity.NewSessions(ctx, sessionConfig)
	if err != nil {
		return err
	}
	defer sessions.Close()
	address := app.ListenAddress
	server := &http.Server{
		Addr:              address,
		Handler:           routes(sessions, profiles, diagnosticSystem, noteSystem, emailSystem, hub, pages),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	var background sync.WaitGroup
	background.Go(func() { notesPublisher.Run(ctx) })
	background.Go(func() { emailPublisher.Run(ctx) })
	background.Go(func() { wsapi.PublishStatus(ctx, hub, diagnosticSystem) })
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServe() }()
	slog.Info("listening", "address", address)
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server stopped", "error", err)
		}
		stop()
	}
	_ = sessions.Close()
	hub.Close()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
	}
	background.Wait()
	return nil
}

// recordProfile runs on every signed-in /auth/session request, so a person's
// profile exists before any page loads and its email stays current.
func recordProfile(profiles *userprofiles.System) func(*http.Request, identity.Identity) (any, error) {
	return func(request *http.Request, person identity.Identity) (any, error) {
		return nil, profiles.Record(request.Context(), person.Subject, person.Email)
	}
}

// routes mounts every route on the router, each line naming its kind and,
// for a guarded kind, its permission. The frontend is the one public subtree,
// mounted last.
func routes(sessions *identity.Sessions, profiles *userprofiles.System, diagnosticSystem *diagnostics.System, noteSystem *notes.System, emailSystem *email.System, hub *realtime.Hub, pages http.Handler) http.Handler {
	router := sessions.Router()
	router.Public(httpapi.HealthPattern, httpapi.Health(), identity.PublicOptions{Probe: true})
	router.Public(httpapi.PublicNotesPattern, httpapi.PublicNotes(noteSystem))
	router.Service(httpapi.StatusPattern, access.DiagnosticsRead, httpapi.Status(diagnosticSystem))
	router.Private(httpapi.ListNotesPattern, access.NotesRead, httpapi.ListNotes(noteSystem, profiles))
	router.Private(httpapi.CreateNotePattern, access.NotesWrite, httpapi.CreateNote(noteSystem, profiles))
	router.Private(httpapi.DeleteNotePattern, access.NotesWrite, httpapi.DeleteNote(noteSystem))
	router.Private(httpapi.EmailKeyStatusPattern, access.EmailWrite, httpapi.EmailKeyStatus(emailSystem))
	router.Private(httpapi.SetEmailKeyPattern, access.EmailWrite, httpapi.SetEmailKey(emailSystem))
	router.Private(wsapi.StatusPattern, access.DiagnosticsRead, wsapi.Status(diagnosticSystem, hub))
	router.Private(wsapi.NotesPattern, access.NotesRead, wsapi.Notes(hub))
	router.Private(wsapi.EmailPattern, access.EmailWrite, wsapi.Email(hub))
	router.Public(httpapi.FrontendPattern, pages)
	return router
}
