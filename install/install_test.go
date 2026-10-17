package install

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ovi1kanobe/appkit/config"
)

// fakeHost records commands and owns the user once useradd ran, answering
// with the test's own IDs so chown succeeds on the temporary root.
type fakeHost struct {
	accounts   map[string]account
	commands   []string
	echoed     []bool
	noTerminal bool
}

func newFakeHost() *fakeHost { return &fakeHost{accounts: map[string]account{}} }

func (host *fakeHost) lookup(name string) (account, bool, error) {
	existing, found := host.accounts[name]
	return existing, found, nil
}

func (host *fakeHost) run(_ context.Context, name string, args ...string) error {
	host.commands = append(host.commands, name+" "+strings.Join(args, " "))
	if name == "useradd" {
		host.accounts[args[len(args)-1]] = account{uid: os.Getuid(), gid: os.Getgid(), shell: "/usr/sbin/nologin"}
	}
	return nil
}

func (host *fakeHost) terminal() bool { return !host.noTerminal }

func (host *fakeHost) echo(on bool) error {
	host.echoed = append(host.echoed, on)
	return nil
}

var declarations = []config.Declaration{
	{Name: "LISTEN_ADDRESS", Description: "address", Default: "127.0.0.1:8080"},
	{Name: "APP_ENV", Description: "env", Default: "production"},
	{Name: "RAUTHY_ISSUER", Description: "issuer", Required: true},
	{Name: "RAUTHY_CLIENT_SECRET", Description: "secret"},
	{Name: "APP_MASTER_KEY", Description: "key", Required: true},
	{Name: "DATABASE_PATH", Description: "db", Default: "app.sqlite"},
}

func binary(t *testing.T) string {
	t.Helper()
	executable := filepath.Join(t.TempDir(), "notes")
	if err := os.WriteFile(executable, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return executable
}

func install(t *testing.T, root string, host host, declarations []config.Declaration, executable, answers string) (string, string) {
	t.Helper()
	var output strings.Builder
	installer := Installer{Name: "notes", Declarations: declarations, Input: strings.NewReader(answers), Output: &output}
	if err := installer.run(context.Background(), executable, host, root); err != nil {
		t.Fatal(err)
	}
	environment, err := os.ReadFile(filepath.Join(root, "etc", "notes", "notes.env"))
	if err != nil {
		t.Fatal(err)
	}
	return string(environment), output.String()
}

func TestInstallAsksOnceAndKeepsValuesOnRerun(t *testing.T) {
	root := t.TempDir()
	host := newFakeHost()
	environment, output := install(t, root, host, declarations, binary(t), "\n\nhttps://auth.example/\n hush \n")

	for _, line := range []string{
		`LISTEN_ADDRESS="127.0.0.1:8080"`, `APP_ENV="production"`, `RAUTHY_ISSUER="https://auth.example/"`,
		`RAUTHY_CLIENT_SECRET=" hush "`, `DATABASE_PATH="/var/lib/notes/notes.sqlite"`, `SESSION_DATABASE="/var/lib/notes/sessions.sqlite"`,
	} {
		if !strings.Contains(environment, line+"\n") {
			t.Errorf("environment lacks %s:\n%s", line, environment)
		}
	}
	key := valueOf(t, environment, "APP_MASTER_KEY")
	if len(key) != 44 || !strings.Contains(output, key) {
		t.Errorf("master key %q should be generated and printed once", key)
	}
	if strings.Contains(output, "APP_ENV") || strings.Contains(output, "DATABASE_PATH") {
		t.Errorf("managed variables were asked:\n%s", output)
	}
	if len(host.echoed) != 2 || host.echoed[0] || !host.echoed[1] {
		t.Errorf("secret should turn echo off then on, got %v", host.echoed)
	}
	want := []string{
		"useradd --system --user-group --no-create-home --home-dir " + filepath.Join(root, "var/lib/notes") + " --shell /usr/sbin/nologin notes",
		"systemctl daemon-reload", "systemctl enable notes", "systemctl restart notes",
	}
	if strings.Join(host.commands, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s", strings.Join(host.commands, "\n"))
	}
	assertMode(t, filepath.Join(root, "etc/notes/notes.env"), 0o600)
	assertMode(t, filepath.Join(root, "etc/notes"), 0o700|os.ModeDir)
	assertMode(t, filepath.Join(root, "var/lib/notes"), 0o750|os.ModeDir)
	assertMode(t, filepath.Join(root, "opt/notes/notes"), 0o755)
	unit, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/notes.service"))
	if err != nil || !strings.Contains(string(unit), "ExecStart=/opt/notes/notes\n") {
		t.Errorf("unit: %v\n%s", err, unit)
	}

	// Move the database, add a variable by hand, blank a required one, then
	// rerun from the installed binary with one new declaration.
	path := filepath.Join(root, "etc/notes/notes.env")
	edited := strings.Replace(environment, `RAUTHY_ISSUER="https://auth.example/"`, `RAUTHY_ISSUER=""`, 1)
	edited = strings.Replace(edited, `DATABASE_PATH="/var/lib/notes/notes.sqlite"`, `DATABASE_PATH=/srv/notes.sqlite`, 1)
	if err := os.WriteFile(path, []byte(edited+"EXTRA='by hand'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(root, "opt/notes/notes")
	if err := os.WriteFile(installed, []byte("updated"), 0o755); err != nil {
		t.Fatal(err)
	}
	host.commands = nil
	more := append(append([]config.Declaration(nil), declarations...), config.Declaration{Name: "SMTP_HOST", Description: "mail", Required: true})
	rerun, output := install(t, root, host, more, installed, "https://auth.example/\n\nmail.example\n")
	if valueOf(t, rerun, "APP_MASTER_KEY") != key {
		t.Error("master key changed on rerun")
	}
	if strings.Contains(output, key) {
		t.Error("existing master key was printed again")
	}
	for _, line := range []string{`RAUTHY_ISSUER="https://auth.example/"`, `SMTP_HOST="mail.example"`, `EXTRA="by hand"`, `DATABASE_PATH="/srv/notes.sqlite"`} {
		if !strings.Contains(rerun, line+"\n") {
			t.Errorf("rerun lacks %s:\n%s", line, rerun)
		}
	}
	if !strings.Contains(output, "Kept 2 variables") || !strings.Contains(output, "SMTP_HOST is required.") {
		t.Errorf("rerun should count kept values and insist on the new one:\n%s", output)
	}
	if content, _ := os.ReadFile(installed); string(content) != "updated" {
		t.Error("the installed binary was replaced although it was the running one")
	}
	if strings.Join(host.commands, "\n") != "systemctl daemon-reload\nsystemctl enable notes\nsystemctl restart notes" {
		t.Errorf("rerun commands:\n%s", strings.Join(host.commands, "\n"))
	}
}

func TestInstallRefusesBadNamesAndSharedAccounts(t *testing.T) {
	bad := Installer{Name: "Bad Name", Declarations: declarations, Output: &strings.Builder{}}
	if err := bad.run(context.Background(), binary(t), newFakeHost(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "lowercase") {
		t.Errorf("bad name: %v", err)
	}
	for _, existing := range []account{{uid: 0, shell: "/usr/sbin/nologin"}, {uid: 1000, shell: "/bin/bash"}} {
		host := newFakeHost()
		host.accounts["notes"] = existing
		installer := Installer{Name: "notes", Declarations: declarations, Output: &strings.Builder{}}
		err := installer.run(context.Background(), binary(t), host, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "not a dedicated system account") || len(host.commands) != 0 {
			t.Errorf("account %+v: %v, commands %v", existing, err, host.commands)
		}
	}
}

func TestInstallStopsWhenInputEndsOrIsCancelled(t *testing.T) {
	ended := Installer{Name: "notes", Declarations: declarations, Input: strings.NewReader(""), Output: &strings.Builder{}}
	err := ended.run(context.Background(), binary(t), newFakeHost(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "LISTEN_ADDRESS: input ended") {
		t.Errorf("expected an error naming the unanswered variable, got %v", err)
	}

	never, _ := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := Installer{Name: "notes", Declarations: declarations, Input: never, Output: &strings.Builder{}}
	err = cancelled.run(ctx, binary(t), newFakeHost(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected cancellation, got %v", err)
	}
}

func TestMasterKeyIsNotPrintedWithoutATerminal(t *testing.T) {
	host := newFakeHost()
	host.noTerminal = true
	root := t.TempDir()
	environment, output := install(t, root, host, declarations, binary(t), "\n\nhttps://auth.example/\n\n")
	key := valueOf(t, environment, "APP_MASTER_KEY")
	if strings.Contains(output, key) || !strings.Contains(output, "A master key was generated into") {
		t.Errorf("output should point at the file instead of printing the key:\n%s", output)
	}
}

func TestEnvironmentQuotingRoundTrips(t *testing.T) {
	values := map[string]string{"A": `say "hi" \ there $x`, "B": "plain"}
	rendered := renderEnvironment([]config.Declaration{{Name: "A"}, {Name: "B"}}, values, nil)
	parsed, order := parseEnvironment("# comment\n; also\nexport C=bare\n" + rendered + "D='single'\nE=\"a\\nb\"\n")
	if parsed["A"] != values["A"] || parsed["B"] != "plain" || parsed["C"] != "bare" || parsed["D"] != "single" {
		t.Errorf("parsed %v from:\n%s", parsed, rendered)
	}
	if parsed["E"] != `a\nb` {
		t.Errorf("a backslash before an ordinary character should stay, got %q", parsed["E"])
	}
	if strings.Join(order, ",") != "C,A,B,D,E" {
		t.Errorf("order %v", order)
	}
}

func valueOf(t *testing.T, environment, name string) string {
	t.Helper()
	values, _ := parseEnvironment(environment)
	value, present := values[name]
	if !present {
		t.Fatalf("%s missing from:\n%s", name, environment)
	}
	return value
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != want {
		t.Errorf("%s has mode %v, want %v", path, info.Mode(), want)
	}
}
