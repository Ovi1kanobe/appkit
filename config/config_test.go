package config

import (
	"bytes"
	"log/slog"
	"net/http"
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
	want := "DATABASE_PATH,LISTEN_ADDRESS,APP_ENV,RAUTHY_ISSUER,RAUTHY_CLIENT_ID,RAUTHY_CLIENT_SECRET,APP_ORIGIN,SESSION_DATABASE,CLIENT_ADDRESS,TRUSTED_PROXIES,APP_MASTER_KEY,SMTP_HOST,SMTP_PORT"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("declared %s\nwant     %s", got, want)
	}
	first, host, port := declarations[0], declarations[11], declarations[12]
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

// TestClientAddress checks that CLIENT_ADDRESS and TRUSTED_PROXIES, read
// through AppKit and Check as at startup, key each request by the caller's
// bare address or IPv6 /64, believing a header only from a trusted proxy.
func TestClientAddress(t *testing.T) {
	var warnings bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&warnings, nil)))
	defer slog.SetDefault(defaultLogger)
	const cloudflareStyle = "127.0.0.1,173.245.48.0/20"
	overlong := strings.Repeat("x", 200)
	for _, test := range []struct {
		name, clientAddress, trustedProxies, remoteAddr string
		header                                          http.Header
		address                                         string
		warning                                         bool // the request logs the missing header warning, once
	}{
		{"remote", "remote", "", "192.0.2.1:4321", nil, "192.0.2.1", false},
		{"remote ignores TRUSTED_PROXIES", "remote", "not an address", "192.0.2.1:4321", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "192.0.2.1", false},
		{"remote IPv6 keyed by its /64", "remote", "", "[2001:db8:1:2::99]:443", nil, "2001:db8:1:2::/64", false},
		{"remote IPv4 unmapped from IPv6", "remote", "", "[::ffff:192.0.2.1]:443", nil, "192.0.2.1", false},
		{"header from a trusted address", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", false},
		{"header name in any case", "header:x-forwarded-for", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", false},
		{"header forged earlier entry ignored", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7"}}, "203.0.113.7", false},
		{"header across lines", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"198.51.100.1", "203.0.113.7"}}, "203.0.113.7", false},
		{"header from a trusted range", "header:X-Forwarded-For", "10.0.1.0/24", "10.0.1.5:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", false},
		{"header from trusted IPv6 loopback", "header:X-Forwarded-For", "127.0.0.1,::1", "[::1]:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", false},
		{"header from an IPv4-mapped trusted connection", "header:X-Forwarded-For", "127.0.0.1", "[::ffff:127.0.0.1]:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", false},
		{"header chain of two trusted hops", "header:X-Forwarded-For", cloudflareStyle, "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7, 173.245.48.10"}}, "203.0.113.7", false},
		{"header all trusted keyed by the connection", "header:X-Forwarded-For", cloudflareStyle, "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"173.245.48.10"}}, "127.0.0.1", false},
		{"header from an untrusted connection keyed by it", "header:X-Forwarded-For", "127.0.0.1", "198.51.100.9:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "198.51.100.9", false},
		{"header IPv4 with a port", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"1.2.3.4:51234"}}, "1.2.3.4", false},
		{"header IPv6 with a port keyed by its /64", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"[2001:db8::1]:80"}}, "2001:db8::/64", false},
		{"header zoned address", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"fe80::1%eth0"}}, "fe80::/64", false},
		{"header empty entries skipped", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"203.0.113.7, ,  ", "   "}}, "203.0.113.7", false},
		{"header single-valued", "header:CF-Connecting-IP", "127.0.0.1", "127.0.0.1:5000", http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}, "X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.9", false},
		{"header not an address used as is", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {" unknown "}}, "unknown", false},
		{"header overlong non-address cut to 64 bytes", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {overlong}}, overlong[:64], false},
		{"header missing keyed by the proxy", "header:X-Real-IP", "127.0.0.1", "127.0.0.1:5000", nil, "127.0.0.1", true},
		{"header only blank entries keyed by the proxy", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {" , "}}, "127.0.0.1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("CLIENT_ADDRESS", test.clientAddress)
			t.Setenv("TRUSTED_PROXIES", test.trustedProxies)
			environment := New()
			appKit := environment.AppKit(Defaults{})
			if err := environment.Check(); appKit.ClientAddress == nil || err != nil && (strings.Contains(err.Error(), "CLIENT_ADDRESS") || strings.Contains(err.Error(), "TRUSTED_PROXIES")) {
				t.Fatalf("refused: %v", err)
			}
			request := httptest.NewRequest("GET", "/api/notes/public", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header = test.header
			warnings.Reset()
			// Twice, so a warning shows it is logged once per rule.
			for range 2 {
				if got := appKit.ClientAddress(request); got != test.address {
					t.Fatalf("address %q, want %q", got, test.address)
				}
			}
			want := 0
			if test.warning {
				want = 1
			}
			if count := strings.Count(warnings.String(), "AppKit client address header missing"); count != want {
				t.Fatalf("%d missing header warnings, want %d:\n%s", count, want, warnings.String())
			}
		})
	}
}

// TestClientAddressRefused checks that every value CLIENT_ADDRESS and
// TRUSTED_PROXIES cannot use fails at startup with one problem naming its
// variable.
func TestClientAddressRefused(t *testing.T) {
	for _, test := range []struct {
		name, clientAddress, trustedProxies, problem string
	}{
		{"missing", "", "", "CLIENT_ADDRESS is not set"},
		{"blank", "   ", "", "CLIENT_ADDRESS is not set"},
		{"capitalised remote", "Remote", "", `CLIENT_ADDRESS is invalid: must be remote, for the connection's address when nothing sits in front of the app, or header:<Name>`},
		{"header without a name", "header:", "127.0.0.1", "CLIENT_ADDRESS is invalid: must be remote"},
		{"header name with spaces", "header:X Forwarded For", "127.0.0.1", "CLIENT_ADDRESS is invalid: must be remote"},
		{"bare header name", "X-Forwarded-For", "127.0.0.1", "CLIENT_ADDRESS is invalid: must be remote"},
		{"header Forwarded", "header:forwarded", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Forwarded is not supported, because its for=...;proto=... format is not parsed; use the header the reverse proxy writes plainly, such as header:X-Forwarded-For"},
		{"header Host", "header:host", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Host cannot carry a client address; use the header the reverse proxy sets, such as header:X-Forwarded-For"},
		{"header Authorization", "header:Authorization", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Authorization cannot carry a client address"},
		{"header Proxy-Authorization", "header:Proxy-Authorization", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Proxy-Authorization cannot carry a client address"},
		{"header Cookie", "header:Cookie", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Cookie cannot carry a client address"},
		{"header Content-Length", "header:Content-Length", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Content-Length cannot carry a client address"},
		{"header Transfer-Encoding", "header:Transfer-Encoding", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Transfer-Encoding cannot carry a client address"},
		{"header Connection", "header:Connection", "127.0.0.1", "CLIENT_ADDRESS is invalid: header:Connection cannot carry a client address"},
		{"header without TRUSTED_PROXIES", "header:X-Forwarded-For", "", "TRUSTED_PROXIES is invalid: must list the reverse proxy's addresses or ranges, such as 127.0.0.1,::1, when CLIENT_ADDRESS uses header:<Name>"},
		{"TRUSTED_PROXIES not a range", "header:X-Forwarded-For", "10.0.1.0/33", `TRUSTED_PROXIES is invalid: "10.0.1.0/33" is not an address or CIDR range`},
		{"TRUSTED_PROXIES not an address", "header:X-Forwarded-For", "127.0.0.1,proxy", `TRUSTED_PROXIES is invalid: "proxy" is not an address or CIDR range`},
		{"TRUSTED_PROXIES IPv4-mapped range shorter than /96", "header:X-Forwarded-For", "::ffff:1.2.3.4/80", `TRUSTED_PROXIES is invalid: "::ffff:1.2.3.4/80" is an IPv4-mapped range shorter than /96`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("CLIENT_ADDRESS", test.clientAddress)
			t.Setenv("TRUSTED_PROXIES", test.trustedProxies)
			environment := New()
			appKit := environment.AppKit(Defaults{})
			err := environment.Check()
			if appKit.ClientAddress != nil || err == nil || !strings.Contains(err.Error(), test.problem) {
				t.Fatalf("%v, want %q", err, test.problem)
			}
			if problems := strings.Count(err.Error(), "CLIENT_ADDRESS is ") + strings.Count(err.Error(), "TRUSTED_PROXIES is "); problems != 1 {
				t.Fatalf("%d problems for these variables, want 1: %v", problems, err)
			}
		})
	}
}
