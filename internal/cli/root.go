// Package cli implements the expose command-line interface, dispatching
// subcommands for server, client, login, and API key administration.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/koltyakov/expose/internal/selfupdate"
)

// Run is the main CLI entry point. It parses args and dispatches to the
// appropriate subcommand, returning a process exit code.
func Run(args []string) int {
	var err error
	args, err = selfupdate.ResumeRestart(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "auto-update: restart handoff failed:", err)
		return 1
	}
	resolveVersion()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if len(args) == 0 {
		printUsage()
		return 0
	}

	switch args[0] {
	case "auth":
		return runAuth(ctx, args[1:])
	case "login":
		return runClientLogin(ctx, args[1:])
	case "list":
		return runList(ctx, args[1:])
	case "http":
		return runHTTP(ctx, args[1:])
	case "static":
		return runStatic(ctx, args[1:])
	case "pub":
		return runPub(ctx, args[1:])
	case "up":
		return runUp(ctx, args[1:])
	case "soak":
		return runSoak(ctx, args[1:])
	case "tunnel":
		return runTunnel(ctx, args[1:])
	case "client":
		return runClientCommand(ctx, args[1:])
	case "server":
		return runServer(ctx, args[1:])
	case "apikey":
		return runAPIKeyAdmin(ctx, args[1:])
	case "update":
		return runUpdate(ctx)
	case "version", "--version", "-v":
		printVersion()
		return 0
	case "-h", "--help", "help":
		printUsage()
		return 0
	default:
		return runClient(ctx, args)
	}
}

func runClientCommand(ctx context.Context, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "login":
			return runClientLogin(ctx, args[1:])
		case "list":
			return runList(ctx, args[1:])
		case "http":
			return runHTTP(ctx, args[1:])
		case "static":
			return runStatic(ctx, args[1:])
		case "pub":
			return runPub(ctx, args[1:])
		case "soak":
			return runSoak(ctx, args[1:])
		case "tunnel":
			return runTunnel(ctx, args[1:])
		}
	}
	return runClient(ctx, args)
}
