package cli

import (
	"context"
	"os/signal"
	"syscall"
)

// Run is the main CLI entry point. It parses args and dispatches to the
// appropriate subcommand, returning a process exit code.
func Run(args []string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if len(args) == 0 {
		return runClient(ctx, nil)
	}

	switch args[0] {
	case "login":
		return runClientLogin(args[1:])
	case "http":
		return runHTTP(ctx, args[1:])
	case "up":
		return runUp(ctx, args[1:])
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
			return runClientLogin(args[1:])
		case "http":
			return runHTTP(ctx, args[1:])
		case "tunnel":
			return runTunnel(ctx, args[1:])
		}
	}
	return runClient(ctx, args)
}
