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

	"github.com/Ovi1kanobe/appkit/api"
	"github.com/Ovi1kanobe/appkit/authz"
	"github.com/Ovi1kanobe/appkit/config"
	httpapi "github.com/Ovi1kanobe/appkit/examples/starter/api/http"
	"github.com/Ovi1kanobe/appkit/examples/starter/cli"
	"github.com/Ovi1kanobe/appkit/examples/starter/systems/userprofiles"
	"github.com/Ovi1kanobe/appkit/frontend"
	"github.com/Ovi1kanobe/appkit/identity"
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

// The Rauthy groups that grant this application's roles, one constant per
// group. Every group name starts with the application name,
// because Rauthy groups are shared by all apps.
const membersGroup = "starter-members"

// The application's roles, one per group unless a group grants several.
const memberRole = "member"

// newPolicy defines the application's roles and permissions. Each system adds
// its permission constants from api/access to the roles as it is added. The
// third map lists the Rauthy clients of applications that call this one, by
// client ID, with the roles each gets; nil when no application calls it. The
// last list names the permissions a person may give a key they make for a
// tool; add them as systems are added, never one that moves money, changes
// credentials or endpoints, or is irreversible.
func newPolicy() (*authz.Policy, error) {
	return authz.New(
		map[string][]string{memberRole: {}},
		map[string][]string{membersGroup: {memberRole}},
		nil,
		nil,
	)
}

func run(appKit config.AppKit) error {
	app, sessionConfig := appKit.App, appKit.Sessions
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
		Handler:           routes(sessions, pages),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	// Each system's and publisher's Run starts here with background.Go.
	var background sync.WaitGroup
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
	// The realtime hub, created with the first live system, is closed here, before the server.
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
// for a guarded kind, its permission. The frontend is the one public subtree.
func routes(sessions *identity.Sessions, pages http.Handler) http.Handler {
	router := sessions.Router(identity.RouterConfig{BodyLimit: api.DefaultBodyLimit})
	router.Public(httpapi.HealthPattern, httpapi.Health(), identity.PublicOptions{Probe: true})
	router.Public(httpapi.FrontendPattern, pages)
	return router
}
