// Package install sets an application up as a systemd service on a Linux
// host: a system user, its directories, the binary under /opt, an environment
// file filled in by asking for each variable the application reads, and a
// hardened unit. Running it again keeps every value already in place and asks
// only for variables the current binary declares that the file lacks.
package install

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/Ovi1kanobe/appkit/config"
)

// Installer installs the running executable as the service Name.
type Installer struct {
	Name         string               // binary, user, service, and directory name
	Declarations []config.Declaration // every variable the application reads
	Input        io.Reader            // answers; defaults to stdin
	Output       io.Writer            // prompts and the summary; defaults to stdout
}

// Managed variables are set by the installer and never asked for. The master
// key and APP_ENV are always the installer's; the database paths are set on
// the first install and then kept, so an operator may move a database.
const (
	masterKeyVariable       = "APP_MASTER_KEY"
	environmentVariable     = "APP_ENV"
	databaseVariable        = "DATABASE_PATH"
	sessionDatabaseVariable = "SESSION_DATABASE"
)

var validName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Run installs executable, the path of the running binary, and starts the
// service. It must run as root on a Linux host with systemd.
func (installer Installer) Run(ctx context.Context, executable string) error {
	if runtime.GOOS != "linux" {
		return errors.New("install: only Linux hosts with systemd are supported")
	}
	if os.Geteuid() != 0 {
		return errors.New("install: run as root, for example with sudo")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("install: systemctl was not found; only hosts with systemd are supported")
	}
	return installer.run(ctx, executable, linuxHost{}, "/")
}

// host is what install needs from the operating system, so tests replace it.
type host interface {
	lookup(name string) (account, bool, error)
	run(ctx context.Context, name string, args ...string) error
	terminal() bool     // stdin and stdout are a terminal, so secrets may be shown or hidden
	echo(on bool) error // terminal echo, for typing secrets
}

// account is an existing operating system user.
type account struct {
	uid, gid int
	shell    string
}

// dedicated reports whether the account cannot log in, as a service user should not.
func (existing account) dedicated() bool {
	switch existing.shell {
	case "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
		return existing.uid != 0
	}
	return false
}

// paths is where one application lives on disk. Outside tests root is /, and
// the paths written into the environment file and the unit are always the
// real ones under /, since the service reads them on the host.
type paths struct {
	binary, environmentDir, environment, data, unit string
}

func layout(root, name string) paths {
	return paths{
		binary:         filepath.Join(root, "opt", name, name),
		environmentDir: filepath.Join(root, "etc", name),
		environment:    filepath.Join(root, "etc", name, name+".env"),
		data:           filepath.Join(root, "var", "lib", name),
		unit:           filepath.Join(root, "etc", "systemd", "system", name+".service"),
	}
}

func (installer Installer) run(ctx context.Context, executable string, host host, root string) error {
	if !validName.MatchString(installer.Name) {
		return fmt.Errorf("install: name %q must be lowercase letters, digits, and hyphens", installer.Name)
	}
	if installer.Input == nil {
		installer.Input = os.Stdin
	}
	if installer.Output == nil {
		installer.Output = os.Stdout
	}
	name := installer.Name
	where := layout(root, name)

	serviceUser, err := ensureUser(ctx, host, name, where.data)
	if err != nil {
		return err
	}
	if err := ensureDirectories(where, serviceUser); err != nil {
		return err
	}
	if err := installBinary(executable, where.binary); err != nil {
		return err
	}

	values, extra, err := readEnvironment(where.environment)
	if err != nil {
		return err
	}
	generated := false
	if values[masterKeyVariable] == "" {
		values[masterKeyVariable] = newMasterKey()
		generated = true
	}
	values[environmentVariable] = "production"
	setDefault(values, databaseVariable, filepath.Join("/var/lib", name, name+".sqlite"))
	setDefault(values, sessionDatabaseVariable, filepath.Join("/var/lib", name, "sessions.sqlite"))
	if err := installer.ask(ctx, host, where.environment, values); err != nil {
		return err
	}
	if err := writeFile(where.environment, renderEnvironment(installer.Declarations, values, extra), 0o600); err != nil {
		return err
	}
	if err := writeFile(where.unit, renderUnit(name), 0o644); err != nil {
		return err
	}

	// Each command is idempotent, so every run does all three and a failed
	// first install is completed by the next run.
	for _, args := range [][]string{{"daemon-reload"}, {"enable", name}, {"restart", name}} {
		if err := host.run(ctx, "systemctl", args...); err != nil {
			return err
		}
	}

	installer.summary(host, where, values, generated)
	return nil
}

func setDefault(values map[string]string, name, value string) {
	if values[name] == "" {
		values[name] = value
	}
}

// ensureUser creates the system user and group when missing. An existing
// account is used only when it is a dedicated system account, never root or
// an account someone logs in with.
func ensureUser(ctx context.Context, host host, name, home string) (account, error) {
	existing, found, err := host.lookup(name)
	if err != nil {
		return account{}, err
	}
	if found {
		if !existing.dedicated() {
			return account{}, fmt.Errorf("install: user %s already exists and is not a dedicated system account; choose another name", name)
		}
		return existing, nil
	}
	err = host.run(ctx, "useradd", "--system", "--user-group", "--no-create-home",
		"--home-dir", home, "--shell", "/usr/sbin/nologin", name)
	if err != nil {
		return account{}, err
	}
	existing, found, err = host.lookup(name)
	if err != nil {
		return account{}, err
	}
	if !found {
		return account{}, fmt.Errorf("install: user %s was not found after useradd", name)
	}
	return existing, nil
}

// ensureDirectories creates the installer's directories with their final
// modes and owners, correcting an existing one's mode and owner as well. The
// unit directory belongs to systemd, so it is only created.
func ensureDirectories(where paths, serviceUser account) error {
	owned := []struct {
		path  string
		mode  os.FileMode
		owner *account // nil for root
	}{
		{filepath.Dir(where.binary), 0o755, nil},
		{where.environmentDir, 0o700, nil},
		{where.data, 0o750, &serviceUser},
	}
	for _, directory := range owned {
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		if directory.owner != nil {
			if err := os.Chown(directory.path, directory.owner.uid, directory.owner.gid); err != nil {
				return fmt.Errorf("install: %w", err)
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(where.unit), 0o755); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// installBinary copies the running executable to target by staging and one
// atomic rename, unless it already runs from there.
func installBinary(executable, target string) error {
	source, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("install: executable: %w", err)
	}
	if existing, err := filepath.EvalSymlinks(target); err == nil && existing == source {
		return nil
	}
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("install: executable: %w", err)
	}
	defer file.Close()
	staged, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".install-*")
	if err != nil {
		return fmt.Errorf("install: stage: %w", err)
	}
	_, copyErr := io.Copy(staged, file)
	syncErr := staged.Sync()
	closeErr := staged.Close()
	chmodErr := os.Chmod(staged.Name(), 0o755)
	if err := errors.Join(copyErr, syncErr, closeErr, chmodErr); err != nil {
		os.Remove(staged.Name())
		return fmt.Errorf("install: stage: %w", err)
	}
	if err := os.Rename(staged.Name(), target); err != nil {
		os.Remove(staged.Name())
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// answer is one line typed by the operator, or the error that ended input.
type answer struct {
	line string
	err  error
}

// ask fills values for every declared variable the installer does not
// manage, keeping values already present and asking for the rest. Lines are
// read on their own goroutine so a cancelled context ends the wait.
func (installer Installer) ask(ctx context.Context, host host, path string, values map[string]string) error {
	answers := make(chan answer)
	go func() {
		reader := bufio.NewReader(installer.Input)
		for {
			line, err := reader.ReadString('\n')
			select {
			case answers <- answer{line, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	kept := 0
	for _, declaration := range installer.Declarations {
		if managed(declaration.Name) {
			continue
		}
		if value, present := values[declaration.Name]; present && (value != "" || !declaration.Required) {
			kept++
			continue
		}
		value, err := installer.prompt(ctx, host, answers, declaration)
		if err != nil {
			return err
		}
		values[declaration.Name] = value
	}
	if kept > 0 {
		fmt.Fprintf(installer.Output, "\nKept %d variables already in %s.\n", kept, path)
	}
	return nil
}

// prompt asks for one variable until it has a value, or the default for an
// optional one.
func (installer Installer) prompt(ctx context.Context, host host, answers <-chan answer, declaration config.Declaration) (string, error) {
	fmt.Fprintf(installer.Output, "\n%s\n", declaration.Description)
	for {
		value, err := installer.askOnce(ctx, host, answers, declaration)
		if err != nil {
			return "", err
		}
		if value == "" && !declaration.Required {
			return declaration.Default, nil
		}
		if value != "" {
			return value, nil
		}
		fmt.Fprintf(installer.Output, "%s is required.\n", declaration.Name)
	}
}

func (installer Installer) askOnce(ctx context.Context, host host, answers <-chan answer, declaration config.Declaration) (string, error) {
	if declaration.Required {
		fmt.Fprintf(installer.Output, "%s: ", declaration.Name)
	} else {
		fmt.Fprintf(installer.Output, "%s [%s]: ", declaration.Name, declaration.Default)
	}
	hidden := secret(declaration.Name)
	if hidden {
		if err := host.echo(false); err != nil {
			return "", fmt.Errorf("install: cannot hide %s while typed: %w", declaration.Name, err)
		}
		defer func() {
			host.echo(true)
			fmt.Fprintln(installer.Output)
		}()
	}
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("install: %w", ctx.Err())
	case typed := <-answers:
		if typed.err != nil && (!errors.Is(typed.err, io.EOF) || typed.line == "") {
			return "", fmt.Errorf("install: no answer for %s: input ended", declaration.Name)
		}
		if hidden {
			return strings.TrimRight(typed.line, "\r\n"), nil // a secret keeps its spaces
		}
		return strings.TrimSpace(typed.line), nil
	}
}

func managed(name string) bool {
	switch name {
	case masterKeyVariable, environmentVariable, databaseVariable, sessionDatabaseVariable:
		return true
	}
	return false
}

// secret reports whether a variable's value is hidden while typed, by its name.
func secret(name string) bool {
	for _, suffix := range []string{"_SECRET", "_KEY", "_TOKEN", "_PASSWORD", "_PASS", "_PASSPHRASE", "_CREDENTIALS", "_URL", "_DSN"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func newMasterKey() string {
	key := make([]byte, 32)
	rand.Read(key) // never fails since Go 1.24
	return base64.StdEncoding.EncodeToString(key)
}

// readEnvironment parses an existing environment file: the lines this
// package writes, plus bare and single-quoted values and comments, as
// systemd's EnvironmentFile reads them. It returns the values and, in order,
// any names the application does not declare, which are kept when the file is
// rewritten. A missing file is an empty environment.
func readEnvironment(path string) (map[string]string, []string, error) {
	text, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("install: %w", err)
	}
	values, order := parseEnvironment(string(text))
	return values, order, nil
}

func parseEnvironment(text string) (map[string]string, []string) {
	values := map[string]string{}
	var order []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		name = strings.TrimSpace(strings.TrimPrefix(name, "export "))
		value = unquote(strings.TrimSpace(value))
		if _, seen := values[name]; !seen {
			order = append(order, name)
		}
		values[name] = value
	}
	return values, order
}

// unquote removes one level of quoting. Inside double quotes a backslash
// escapes only a quote, a backslash, a dollar sign, or a backtick, as in
// systemd, and stays in place before any other character.
func unquote(value string) string {
	if len(value) < 2 {
		return value
	}
	quote := value[0]
	if (quote != '"' && quote != '\'') || value[len(value)-1] != quote {
		return value
	}
	inner := value[1 : len(value)-1]
	if quote == '\'' {
		return inner
	}
	var out strings.Builder
	for index := 0; index < len(inner); index++ {
		if inner[index] == '\\' && index+1 < len(inner) && strings.IndexByte("\"\\$`", inner[index+1]) >= 0 {
			index++
		}
		out.WriteByte(inner[index])
	}
	return out.String()
}

// renderEnvironment writes declared variables in declaration order, then any
// others the file already held, each double-quoted for systemd.
func renderEnvironment(declarations []config.Declaration, values map[string]string, existing []string) string {
	var out strings.Builder
	written := map[string]bool{}
	write := func(name string) {
		if written[name] {
			return
		}
		value, present := values[name]
		if !present {
			return
		}
		written[name] = true
		fmt.Fprintf(&out, "%s=%s\n", name, quote(value))
	}
	for _, declaration := range declarations {
		write(declaration.Name)
	}
	for _, name := range []string{masterKeyVariable, environmentVariable, databaseVariable, sessionDatabaseVariable} {
		write(name)
	}
	for _, name := range existing {
		write(name)
	}
	return out.String()
}

func quote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

// renderUnit is the service: a dedicated user, restarted while Rauthy is
// unreachable, with the hardening a Go server on loopback with SQLite needs
// nothing from.
func renderUnit(name string) string {
	return fmt.Sprintf(`[Unit]
Description=%[1]s
After=network-online.target
Wants=network-online.target

[Service]
User=%[1]s
Group=%[1]s
WorkingDirectory=/var/lib/%[1]s
EnvironmentFile=/etc/%[1]s/%[1]s.env
ExecStart=/opt/%[1]s/%[1]s
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/%[1]s
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
`, name)
}

// writeFile replaces path's content with one atomic rename.
func writeFile(path, content string, mode os.FileMode) error {
	staged, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".install-*")
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	_, writeErr := staged.WriteString(content)
	syncErr := staged.Sync()
	closeErr := staged.Close()
	chmodErr := os.Chmod(staged.Name(), mode)
	if err := errors.Join(writeErr, syncErr, closeErr, chmodErr); err != nil {
		os.Remove(staged.Name())
		return fmt.Errorf("install: %w", err)
	}
	if err := os.Rename(staged.Name(), path); err != nil {
		os.Remove(staged.Name())
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// summary tells the operator where everything is. A generated master key is
// shown only on a terminal, so it never lands in a captured log.
func (installer Installer) summary(host host, where paths, values map[string]string, generatedKey bool) {
	name := installer.Name
	fmt.Fprintf(installer.Output, `
%[1]s is installed and started; check it with: systemctl status %[1]s

  binary       %[2]s
  environment  %[3]s
  data         %[4]s
`, name, where.binary, where.environment, where.data)
	switch {
	case generatedKey && host.terminal():
		fmt.Fprintf(installer.Output, "\nMaster key, store a copy in a password manager now; losing it loses every stored credential:\n  %s\n", values[masterKeyVariable])
	case generatedKey:
		fmt.Fprintf(installer.Output, "\nA master key was generated into %s; copy %s to a password manager now, since losing it loses every stored credential.\n", where.environment, masterKeyVariable)
	}
	if listen := values["LISTEN_ADDRESS"]; listen != "" {
		fmt.Fprintf(installer.Output, "\nPoint the reverse proxy at http://%s and pass the original Host header.\n", listen)
	}
	fmt.Fprintf(installer.Output, "Update with: sudo %s update && sudo systemctl restart %s\n", where.binary, name)
}

// linuxHost is the real operating system.
type linuxHost struct{}

func (linuxHost) lookup(name string) (account, bool, error) {
	found, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return account{}, false, nil
	}
	if err != nil {
		return account{}, false, fmt.Errorf("install: %w", err)
	}
	uid, uidErr := strconv.Atoi(found.Uid)
	gid, gidErr := strconv.Atoi(found.Gid)
	if err := errors.Join(uidErr, gidErr); err != nil {
		return account{}, false, fmt.Errorf("install: user %s: %w", name, err)
	}
	shell, err := loginShell(name)
	if err != nil {
		return account{}, false, err
	}
	return account{uid: uid, gid: gid, shell: shell}, true, nil
}

// loginShell reads the account's shell from /etc/passwd, which os/user does
// not expose. An account not listed there has no known shell.
func loginShell(name string) (string, error) {
	text, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", fmt.Errorf("install: %w", err)
	}
	for _, line := range strings.Split(string(text), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == name {
			return fields[6], nil
		}
	}
	return "", nil
}

func (linuxHost) run(ctx context.Context, name string, args ...string) error {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (linuxHost) terminal() bool {
	return characterDevice(os.Stdin) && characterDevice(os.Stdout)
}

func characterDevice(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// echo turns terminal echo off or on for stdin, so a secret is not shown
// while typed. It does nothing when stdin is not a terminal.
func (linuxHost) echo(on bool) error {
	if !characterDevice(os.Stdin) {
		return nil
	}
	flag := "-echo"
	if on {
		flag = "echo"
	}
	command := exec.Command("stty", flag)
	command.Stdin = os.Stdin
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("stty %s: %w: %s", flag, err, strings.TrimSpace(string(output)))
	}
	return nil
}
