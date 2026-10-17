// Package cli turns the binary's arguments into one action: serve, version,
// update, install, or help. Operator commands are added here, one function each,
// calling the same systems the routes use.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/Ovi1kanobe/appkit/config"
	"github.com/Ovi1kanobe/appkit/install"
	"github.com/Ovi1kanobe/appkit/selfupdate"
)

const (
	name       = "starter"
	repository = "Ovi1kanobe/starter"
)

// Run executes args and returns the process exit code. With no arguments it
// calls serve and runs until that returns. declare declares every variable
// the application reads, so install can ask for each one.
func Run(args []string, serve func() error, declare func(*config.Environment)) int {
	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	switch command {
	case "":
		if err := serve(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			return 1
		}
		return 0
	case "version", "--version":
		fmt.Println(selfupdate.Version())
		return 0
	case "update":
		return update(args[1:])
	case "install":
		return installService(declare)
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", name, command)
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: %s [command]

  (none)             run the server
  version            print the version
  update             install the latest release over this binary
  update --check     report whether a newer release exists
  install            set this binary up as a systemd service, asking for each variable
  help               show this

update reads a GitHub token for a private repository from --token or GITHUB_TOKEN.
install runs as root on Linux and is safe to run again after an update.
`, name)
}

func installService(declare func(*config.Environment)) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	environment := config.New()
	declare(environment)
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	installer := install.Installer{Name: name, Declarations: environment.Declarations()}
	if err := installer.Run(ctx, executable); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	return 0
}

func update(args []string) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	check := flags.Bool("check", false, "report whether a newer release exists without installing it")
	token := flags.String("token", os.Getenv("GITHUB_TOKEN"), "GitHub token for a private repository")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	updater := selfupdate.Updater{Repository: repository, Name: name, Token: *token}
	current := selfupdate.Version()
	if *check {
		release, err := updater.Check(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			return 1
		}
		if release.Newer {
			fmt.Printf("%s is available; this is %s\n", release.Version, current)
		} else {
			fmt.Printf("%s is current\n", current)
		}
		return 0
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	installed, err := updater.Update(ctx, executable)
	if errors.Is(err, selfupdate.ErrCurrent) {
		fmt.Printf("%s is current\n", current)
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		return 1
	}
	fmt.Printf("installed %s; restart the service to run it\n", installed)
	return 0
}
