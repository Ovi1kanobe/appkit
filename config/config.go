// Package config declares the environment variables an application reads and
// checks them all at once before it starts. Environment variables hold
// deployment values and secrets only; everything else belongs in code.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/Ovi1kanobe/appkit/encryption"
	"github.com/Ovi1kanobe/appkit/identity"
)

// Environment collects declarations. AppKit packages declare their own
// variables through it, and the application adds its own.
type Environment struct {
	declarations []Declaration
	defaults     [][2]string // name, default
	problems     []string
}

// Declaration is one variable the application reads, as declared through
// Required or Optional.
type Declaration struct {
	Name        string
	Description string
	Required    bool
	Default     string // optional variables only
}

// New starts an empty set of declarations read from the process environment.
func New() *Environment {
	return &Environment{}
}

// Required declares a variable that must be set and returns its value.
func (environment *Environment) Required(name, description string) string {
	environment.declarations = append(environment.declarations, Declaration{Name: name, Description: description, Required: true})
	value, _ := os.LookupEnv(name)
	if strings.TrimSpace(value) == "" {
		environment.problems = append(environment.problems, fmt.Sprintf("%s is not set: %s", name, description))
	}
	return value
}

// Optional declares a variable with a default and returns its value.
func (environment *Environment) Optional(name, fallback, description string) string {
	environment.declarations = append(environment.declarations, Declaration{Name: name, Description: description, Default: fallback})
	if value, _ := os.LookupEnv(name); strings.TrimSpace(value) != "" {
		return value
	}
	environment.defaults = append(environment.defaults, [2]string{name, fallback})
	return fallback
}

// Declarations returns every variable declared so far, in declaration order,
// so a command can list or ask for them without starting the application.
func (environment *Environment) Declarations() []Declaration {
	return append([]Declaration(nil), environment.declarations...)
}

// Invalid records a declared variable whose value cannot be used.
func (environment *Environment) Invalid(name, reason string) {
	environment.problems = append(environment.problems, fmt.Sprintf("%s is invalid: %s", name, reason))
}

// Check returns every missing or invalid variable in one error. When there
// are none and APP_ENV is development, it logs each optional variable that
// uses its default.
func (environment *Environment) Check() error {
	if len(environment.problems) > 0 {
		return errors.New("environment:\n  " + strings.Join(environment.problems, "\n  "))
	}
	if value, _ := os.LookupEnv("APP_ENV"); strings.TrimSpace(value) != "development" {
		return nil
	}
	for _, variable := range environment.defaults {
		slog.Info("using default", "variable", variable[0], "value", variable[1])
	}
	return nil
}

// Defaults replaces AppKit's defaults for the application-wide variables.
// Empty fields keep AppKit's: app.sqlite, 127.0.0.1:8080, and production.
type Defaults struct {
	DatabasePath  string // DATABASE_PATH
	ListenAddress string // LISTEN_ADDRESS
	Environment   string // APP_ENV
}

// AppSettings are the application-wide values the application runs with.
type AppSettings struct {
	DatabasePath  string
	ListenAddress string
	Environment   string
}

// Development reports whether APP_ENV is development.
func (settings AppSettings) Development() bool { return settings.Environment == "development" }

// AppKit holds every value AppKit reads from the environment.
type AppKit struct {
	App       AppSettings
	Sessions  identity.SessionConfig // the application still sets Policy
	MasterKey *encryption.Key        // nil when APP_MASTER_KEY is missing or invalid; Check reports why
}

// AppKit declares and reads every AppKit variable. An application usually
// passes config.Defaults{}.
func (environment *Environment) AppKit(defaults Defaults) AppKit {
	fallback := func(value, appKitDefault string) string {
		if value != "" {
			return value
		}
		return appKitDefault
	}
	appKit := AppKit{
		App: AppSettings{
			DatabasePath:  environment.Optional("DATABASE_PATH", fallback(defaults.DatabasePath, "app.sqlite"), "application database file"),
			ListenAddress: environment.Optional("LISTEN_ADDRESS", fallback(defaults.ListenAddress, "127.0.0.1:8080"), "address the server listens on"),
			Environment:   environment.Optional("APP_ENV", fallback(defaults.Environment, "production"), "development serves the frontend from disk and logs defaults"),
		},
		Sessions: identity.SessionConfig{
			Issuer:       environment.Required("RAUTHY_ISSUER", "Rauthy issuer URL exactly as Rauthy reports it, including any trailing slash"),
			ClientID:     environment.Required("RAUTHY_CLIENT_ID", "Rauthy client ID"),
			ClientSecret: environment.Optional("RAUTHY_CLIENT_SECRET", "", "Rauthy client secret; confidential clients only"),
			Origin:       environment.Required("APP_ORIGIN", "public origin users open, such as https://app.example.com or http://localhost:8080"),
			DatabasePath: environment.Optional("SESSION_DATABASE", "appkit-sessions.sqlite", "AppKit session database file"),
		},
	}
	if encoded := environment.Required("APP_MASTER_KEY", "base64 key that encrypts stored credentials; create with openssl rand -base64 32 and keep a copy outside the server"); encoded != "" {
		key, err := encryption.ParseKey(encoded)
		if err != nil {
			environment.Invalid("APP_MASTER_KEY", "must be 32 random bytes in base64; create one with openssl rand -base64 32")
		}
		appKit.MasterKey = key
	}
	return appKit
}
