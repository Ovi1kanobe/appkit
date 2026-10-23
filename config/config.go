// Package config declares the environment variables an application reads and
// checks them all at once before it starts. Environment variables hold
// deployment values and secrets only; everything else belongs in code.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"os"
	"strings"
	"sync"

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
	Sessions  identity.SessionConfig // the application still sets Policy, and may set KeyLifetime and KeyAdminPermission
	MasterKey *encryption.Key        // nil when APP_MASTER_KEY is missing or invalid; Check reports why
	// ClientAddress returns the address a request came from, for
	// identity.RouterConfig; nil when CLIENT_ADDRESS is missing or invalid,
	// and Check reports why.
	ClientAddress func(*http.Request) string
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
	clientAddress := environment.Required("CLIENT_ADDRESS", "where a request's client address comes from: remote for the connection's address, when nothing sits in front of the app, or header:<Name>, such as header:X-Forwarded-For, for the header the reverse proxy sets")
	trustedProxies := environment.Optional("TRUSTED_PROXIES", "", "comma-separated addresses or CIDR ranges of the reverse proxies, such as 127.0.0.1,::1; required when CLIENT_ADDRESS uses header:<Name>")
	// Required already reports a blank value, so only a non-blank one is parsed.
	if strings.TrimSpace(clientAddress) != "" {
		rule, err := ParseClientAddress(clientAddress, trustedProxies)
		var invalid *VariableError
		if errors.As(err, &invalid) {
			environment.Invalid(invalid.Name, invalid.Reason)
		}
		appKit.ClientAddress = rule
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

// VariableError is a value ParseClientAddress refuses, naming the variable
// it came from and why.
type VariableError struct {
	Name, Reason string
}

func (err *VariableError) Error() string { return err.Name + " is invalid: " + err.Reason }

// unusableHeaders cannot carry a client address: each holds the request's
// own host, credentials, or framing, never the address a proxy appends.
var unusableHeaders = []string{"Host", "Authorization", "Proxy-Authorization", "Cookie", "Content-Length", "Transfer-Encoding", "Connection"}

// ParseClientAddress reads CLIENT_ADDRESS and TRUSTED_PROXIES into the rule
// that returns the address a request came from, as the key one caller's rate
// limit is counted under. CLIENT_ADDRESS takes exactly two forms:
//
//   - remote: the connection's address, for an app nothing sits in front of.
//     TRUSTED_PROXIES is ignored.
//   - header:<Name>: the named header, believed only from a connection whose
//     address TRUSTED_PROXIES lists. Its comma-separated entries are walked
//     from the right, each trusted proxy skipped, and the first other entry
//     taken, so header:X-Forwarded-For takes the address the outermost
//     trusted proxy saw, which the client cannot forge. An untrusted
//     connection, or one whose entries are all trusted, is keyed by its own
//     address.
//
// Each address loses its port, IPv4 is unmapped from IPv6, and IPv6 is cut to
// its /64, since one network is one caller; a value that is not an address is
// used as is, cut to 64 bytes. header:Forwarded is refused, since its RFC 7239
// format is not parsed. An error is a *VariableError.
func ParseClientAddress(clientAddress, trustedProxies string) (func(*http.Request) string, error) {
	clientAddress = strings.TrimSpace(clientAddress)
	if clientAddress == "remote" {
		return func(request *http.Request) string { return addressKey(request.RemoteAddr) }, nil
	}
	name, found := strings.CutPrefix(clientAddress, "header:")
	if !found || !validHeaderName(name) {
		return nil, &VariableError{"CLIENT_ADDRESS", fmt.Sprintf("must be remote, for the connection's address when nothing sits in front of the app, or header:<Name>, such as header:X-Forwarded-For, for the header the reverse proxy sets; got %q", clientAddress)}
	}
	name = textproto.CanonicalMIMEHeaderKey(name)
	if name == "Forwarded" {
		return nil, &VariableError{"CLIENT_ADDRESS", "header:Forwarded is not supported, because its for=...;proto=... format is not parsed; use the header the reverse proxy writes plainly, such as header:X-Forwarded-For"}
	}
	for _, unusable := range unusableHeaders {
		if name == unusable {
			return nil, &VariableError{"CLIENT_ADDRESS", fmt.Sprintf("header:%s cannot carry a client address; use the header the reverse proxy sets, such as header:X-Forwarded-For", name)}
		}
	}
	trusted, err := parseTrustedProxies(trustedProxies)
	if err != nil {
		return nil, err
	}
	var warnMissing sync.Once
	return func(request *http.Request) string {
		connection, parsed := parseAddress(request.RemoteAddr)
		if !parsed || !containsAddress(trusted, connection) {
			return addressKey(request.RemoteAddr)
		}
		entries := strings.Split(strings.Join(request.Header.Values(name), ","), ",")
		sawEntry := false
		for index := len(entries) - 1; index >= 0; index-- {
			entry := strings.TrimSpace(entries[index])
			if entry == "" {
				continue
			}
			sawEntry = true
			if address, parsed := parseAddress(entry); parsed && containsAddress(trusted, address) {
				continue
			}
			return addressKey(entry)
		}
		if !sawEntry {
			warnMissing.Do(func() {
				slog.Warn("AppKit client address header missing: the reverse proxy is not setting it, so every caller through the proxy shares one rate limit bucket", "header", name, "path", request.URL.Path)
			})
		}
		return addressKey(request.RemoteAddr)
	}, nil
}

// parseTrustedProxies reads TRUSTED_PROXIES: comma-separated addresses or
// CIDR ranges, at least one.
func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	var trusted []netip.Prefix
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, &VariableError{"TRUSTED_PROXIES", fmt.Sprintf("%q is not an address or CIDR range, such as 127.0.0.1 or 10.0.1.0/24", entry)}
			}
			if prefix.Addr().Is4In6() {
				// Shorter than /96 would reach past the mapped range into all of IPv4.
				if prefix.Bits() < 96 {
					return nil, &VariableError{"TRUSTED_PROXIES", fmt.Sprintf("%q is an IPv4-mapped range shorter than /96; write the IPv4 range itself, such as 10.0.1.0/24", entry)}
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			trusted = append(trusted, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, &VariableError{"TRUSTED_PROXIES", fmt.Sprintf("%q is not an address or CIDR range, such as 127.0.0.1 or 10.0.1.0/24", entry)}
		}
		address = address.Unmap().WithZone("")
		trusted = append(trusted, netip.PrefixFrom(address, address.BitLen()))
	}
	if len(trusted) == 0 {
		return nil, &VariableError{"TRUSTED_PROXIES", "must list the reverse proxy's addresses or ranges, such as 127.0.0.1,::1, when CLIENT_ADDRESS uses header:<Name>"}
	}
	return trusted, nil
}

// containsAddress reports whether address is within any trusted range.
func containsAddress(trusted []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// parseAddress reads an address with or without a port, IPv6 with or
// without brackets, unmapping IPv4 from IPv6 and dropping any zone.
func parseAddress(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap().WithZone(""), true
}

// maxNonAddressKey caps a key that is not an address, so an odd header entry
// a proxy passes on cannot make one key arbitrarily large.
const maxNonAddressKey = 64

// addressKey is the key one caller is counted under: the bare address, or
// for IPv6 its /64 network; a value that is not an address is used as is,
// trimmed and cut to maxNonAddressKey bytes.
func addressKey(value string) string {
	address, parsed := parseAddress(value)
	if !parsed {
		value = strings.TrimSpace(value)
		if len(value) > maxNonAddressKey {
			value = value[:maxNonAddressKey]
		}
		return value
	}
	if address.Is6() {
		network, _ := address.Prefix(64)
		return network.String()
	}
	return address.String()
}

// validHeaderName reports whether name is a non-empty HTTP header name: only
// letters, digits, and the token punctuation RFC 9110 allows.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		isLetterOrDigit := character < 128 && (character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9')
		if !isLetterOrDigit && !strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			return false
		}
	}
	return true
}
