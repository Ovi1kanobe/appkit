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

// TestClientAddress checks that CLIENT_ADDRESS accepts exactly remote and
// header:<Name>, that a header is believed only from TRUSTED_PROXIES, that
// each request is keyed by the caller's bare address or IPv6 /64, and that
// every refused value fails at startup naming its variable.
func TestClientAddress(t *testing.T) {
	var warnings bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&warnings, nil)))
	defer slog.SetDefault(defaultLogger)
	const cloudflareStyle = "127.0.0.1,173.245.48.0/20"
	for _, test := range []struct {
		name, clientAddress, trustedProxies, remoteAddr string
		header                                          http.Header
		address, problem                                string
	}{
		{"remote", "remote", "", "192.0.2.1:4321", nil, "192.0.2.1", ""},
		{"remote ignores TRUSTED_PROXIES", "remote", "not an address", "192.0.2.1:4321", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "192.0.2.1", ""},
		{"remote IPv6 keyed by its /64", "remote", "", "[2001:db8:1:2::99]:443", nil, "2001:db8:1:2::/64", ""},
		{"remote IPv4 unmapped from IPv6", "remote", "", "[::ffff:192.0.2.1]:443", nil, "192.0.2.1", ""},
		{"header from a trusted address", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", ""},
		{"header name in any case", "header:x-forwarded-for", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", ""},
		{"header forged earlier entry ignored", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7"}}, "203.0.113.7", ""},
		{"header across lines", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"198.51.100.1", "203.0.113.7"}}, "203.0.113.7", ""},
		{"header from a trusted range", "header:X-Forwarded-For", "10.0.1.0/24", "10.0.1.5:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", ""},
		{"header from trusted IPv6 loopback", "header:X-Forwarded-For", "127.0.0.1,::1", "[::1]:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.7", ""},
		{"header chain of two trusted hops", "header:X-Forwarded-For", cloudflareStyle, "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"198.51.100.1, 203.0.113.7, 173.245.48.10"}}, "203.0.113.7", ""},
		{"header all trusted keyed by the connection", "header:X-Forwarded-For", cloudflareStyle, "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"173.245.48.10"}}, "127.0.0.1", ""},
		{"header from an untrusted connection keyed by it", "header:X-Forwarded-For", "127.0.0.1", "198.51.100.9:5000", http.Header{"X-Forwarded-For": {"203.0.113.7"}}, "198.51.100.9", ""},
		{"header IPv4 with a port", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"1.2.3.4:51234"}}, "1.2.3.4", ""},
		{"header IPv6 with a port keyed by its /64", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"[2001:db8::1]:80"}}, "2001:db8::/64", ""},
		{"header single-valued", "header:CF-Connecting-IP", "127.0.0.1", "127.0.0.1:5000", http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}, "X-Forwarded-For": {"203.0.113.7"}}, "203.0.113.9", ""},
		{"header not an address used as is", "header:X-Forwarded-For", "127.0.0.1", "127.0.0.1:5000", http.Header{"X-Forwarded-For": {"unknown"}}, "unknown", ""},
		{"header missing keyed by the proxy, once warned", "header:X-Real-IP", "127.0.0.1", "127.0.0.1:5000", nil, "127.0.0.1", ""},
		{"missing", "", "", "", nil, "", "CLIENT_ADDRESS is not set"},
		{"capitalised remote", "Remote", "", "", nil, "", `CLIENT_ADDRESS is invalid: must be remote, for the connection's address when nothing sits in front of the app, or header:<Name>`},
		{"header without a name", "header:", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: must be remote"},
		{"header name with spaces", "header:X Forwarded For", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: must be remote"},
		{"bare header name", "X-Forwarded-For", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: must be remote"},
		{"header without TRUSTED_PROXIES", "header:X-Forwarded-For", "", "", nil, "", "TRUSTED_PROXIES is invalid: must list the reverse proxy's addresses or ranges, such as 127.0.0.1,::1, when CLIENT_ADDRESS uses header:<Name>"},
		{"TRUSTED_PROXIES not a range", "header:X-Forwarded-For", "10.0.1.0/33", "", nil, "", `TRUSTED_PROXIES is invalid: "10.0.1.0/33" is not an address or CIDR range`},
		{"TRUSTED_PROXIES not an address", "header:X-Forwarded-For", "127.0.0.1,proxy", "", nil, "", `TRUSTED_PROXIES is invalid: "proxy" is not an address or CIDR range`},
		{"header Host", "header:host", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: header:Host cannot carry a client address; use the header the reverse proxy sets, such as header:X-Forwarded-For"},
		{"header Authorization", "header:Authorization", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: header:Authorization cannot carry a client address"},
		{"header Proxy-Authorization", "header:Proxy-Authorization", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: header:Proxy-Authorization cannot carry a client address"},
		{"header Cookie", "header:Cookie", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: header:Cookie cannot carry a client address"},
		{"header Content-Length", "header:Content-Length", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: header:Content-Length cannot carry a client address"},
		{"header Transfer-Encoding", "header:Transfer-Encoding", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: header:Transfer-Encoding cannot carry a client address"},
		{"header Connection", "header:Connection", "127.0.0.1", "", nil, "", "CLIENT_ADDRESS is invalid: header:Connection cannot carry a client address"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("CLIENT_ADDRESS", test.clientAddress)
			t.Setenv("TRUSTED_PROXIES", test.trustedProxies)
			environment := New()
			appKit := environment.AppKit(Defaults{})
			err := environment.Check()
			if test.problem != "" {
				if appKit.ClientAddress != nil || err == nil || !strings.Contains(err.Error(), test.problem) {
					t.Fatalf("%v, want %q", err, test.problem)
				}
				return
			}
			if appKit.ClientAddress == nil || err != nil && (strings.Contains(err.Error(), "CLIENT_ADDRESS") || strings.Contains(err.Error(), "TRUSTED_PROXIES")) {
				t.Fatalf("refused: %v", err)
			}
			request := httptest.NewRequest("GET", "/api/notes/public", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header = test.header
			// Twice, so the missing header warning shows it is logged once.
			for range 2 {
				if got := appKit.ClientAddress(request); got != test.address {
					t.Fatalf("address %q, want %q", got, test.address)
				}
			}
		})
	}
	if count := strings.Count(warnings.String(), "AppKit client address header missing"); count != 1 || !strings.Contains(warnings.String(), "header=X-Real-Ip") {
		t.Fatalf("%d missing header warnings, want 1 naming the header:\n%s", count, warnings.String())
	}
}
