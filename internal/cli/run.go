package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/config"
	ilog "github.com/koltyakov/expose/internal/log"
	"github.com/koltyakov/expose/internal/server"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func Run(args []string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if len(args) == 0 {
		return runClient(ctx, nil)
	}

	switch args[0] {
	case "client":
		return runClient(ctx, args[1:])
	case "server":
		return runServer(ctx, args[1:])
	case "-h", "--help", "help":
		printUsage()
		return 0
	default:
		return runClient(ctx, args)
	}
}

func runClient(ctx context.Context, args []string) int {
	cfg, err := config.ParseClientFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}
	logger := ilog.New("info")
	c := client.New(cfg, logger)
	if err := c.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "client error:", err)
		return 1
	}
	return 0
}

func runServer(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "apikey" {
		return runAPIKeyAdmin(ctx, args[1:])
	}

	cfg, err := config.ParseServerFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server config error:", err)
		return 2
	}
	logger := ilog.New(cfg.LogLevel)

	store, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		return 1
	}
	defer store.Close()

	s := server.New(cfg, store, logger)
	if err := s.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		return 1
	}
	return 0
}

func runAPIKeyAdmin(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: expose server apikey <create|list|revoke> [flags]")
		return 2
	}
	switch args[0] {
	case "create":
		return runAPIKeyCreate(ctx, args[1:])
	case "list":
		return runAPIKeyList(ctx, args[1:])
	case "revoke":
		return runAPIKeyRevoke(ctx, args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown apikey command:", args[0])
		return 2
	}
}

func runAPIKeyCreate(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apikey-create", flag.ContinueOnError)
	var dbPath, name, pepper string
	fs.StringVar(&dbPath, "db", envOr("EXPOSE_DB_PATH", "./expose.db"), "sqlite db path")
	fs.StringVar(&name, "name", "default", "key label")
	fs.StringVar(&pepper, "api-key-pepper", envOr("EXPOSE_API_KEY_PEPPER", ""), "hash pepper")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if pepper == "" {
		fmt.Fprintln(os.Stderr, "missing --api-key-pepper or EXPOSE_API_KEY_PEPPER")
		return 2
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		return 1
	}
	defer store.Close()

	plain, err := auth.GenerateAPIKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate key:", err)
		return 1
	}
	hash := auth.HashAPIKey(plain, pepper)
	rec, err := store.CreateAPIKey(ctx, name, hash)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create key:", err)
		return 1
	}
	fmt.Println("id:", rec.ID)
	fmt.Println("name:", rec.Name)
	fmt.Println("api_key:", plain)
	return 0
}

func runAPIKeyList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apikey-list", flag.ContinueOnError)
	var dbPath string
	fs.StringVar(&dbPath, "db", envOr("EXPOSE_DB_PATH", "./expose.db"), "sqlite db path")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		return 1
	}
	defer store.Close()

	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list keys:", err)
		return 1
	}
	for _, k := range keys {
		revoked := "false"
		if k.RevokedAt != nil {
			revoked = "true"
		}
		fmt.Printf("%s\t%s\trevoked=%s\tcreated=%s\n", k.ID, k.Name, revoked, k.CreatedAt.Format("2006-01-02T15:04:05Z"))
	}
	return 0
}

func runAPIKeyRevoke(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apikey-revoke", flag.ContinueOnError)
	var dbPath, id string
	fs.StringVar(&dbPath, "db", envOr("EXPOSE_DB_PATH", "./expose.db"), "sqlite db path")
	fs.StringVar(&id, "id", "", "key id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "missing --id")
		return 2
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		return 1
	}
	defer store.Close()

	if err := store.RevokeAPIKey(ctx, id); err != nil {
		fmt.Fprintln(os.Stderr, "revoke key:", err)
		return 1
	}
	fmt.Println("revoked:", id)
	return 0
}

func printUsage() {
	fmt.Println(`expose - simple BYOI tunnel tool

Usage:
  expose [client-flags]            # default: client mode
  expose client [flags]
  expose server [flags]
  expose server apikey create [flags]
  expose server apikey list [flags]
  expose server apikey revoke [flags]`)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
