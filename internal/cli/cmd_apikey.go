package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func runAPIKeyAdmin(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: expose apikey <create|list|revoke|set-limit> [flags]")
		return 2
	}
	switch args[0] {
	case "create":
		return runAPIKeyCreate(ctx, args[1:])
	case "list":
		return runAPIKeyList(ctx, args[1:])
	case "revoke":
		return runAPIKeyRevoke(ctx, args[1:])
	case "set-limit":
		return runAPIKeySetLimit(ctx, args[1:])
	default:
		fmt.Fprintln(os.Stderr, "unknown apikey command:", args[0])
		return 2
	}
}

func runAPIKeyCreate(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apikey-create", flag.ContinueOnError)
	var dbPath, name, pepper string
	var tunnelLimit int
	fs.StringVar(&dbPath, "db", defaultDBPath(), "sqlite db path")
	fs.StringVar(&name, "name", "default", "key label")
	fs.StringVar(&pepper, "api-key-pepper", envOr("EXPOSE_API_KEY_PEPPER", ""), "hash pepper override")
	fs.IntVar(&tunnelLimit, "tunnel-limit", -1, "max active tunnels for this key (-1 = unlimited)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	store, code := openSQLiteStoreOrExit(dbPath)
	if code != 0 {
		return code
	}
	defer func() { _ = store.Close() }()

	resolvedPepper, err := resolveServerPepper(ctx, store, pepper)
	if err != nil {
		fmt.Fprintln(os.Stderr, "apikey create error:", err)
		return 1
	}

	plain, err := auth.GenerateAPIKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate key:", err)
		return 1
	}
	hash := auth.HashAPIKey(plain, resolvedPepper)
	rec, err := store.CreateAPIKeyWithLimit(ctx, name, hash, tunnelLimit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create key:", err)
		return 1
	}
	fmt.Println("id:", rec.ID)
	fmt.Println("name:", rec.Name)
	fmt.Println("api_key:", plain)
	fmt.Println("tunnel_limit:", formatTunnelLimit(rec.TunnelLimit))
	return 0
}

func runAPIKeyList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apikey-list", flag.ContinueOnError)
	var dbPath string
	fs.StringVar(&dbPath, "db", defaultDBPath(), "sqlite db path")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	store, code := openSQLiteStoreOrExit(dbPath)
	if code != 0 {
		return code
	}
	defer func() { _ = store.Close() }()

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
		fmt.Printf("%s\t%s\trevoked=%s\ttunnel_limit=%s\tcreated=%s\n", k.ID, k.Name, revoked, formatTunnelLimit(k.TunnelLimit), k.CreatedAt.Format("2006-01-02T15:04:05Z"))
	}
	return 0
}

func runAPIKeyRevoke(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apikey-revoke", flag.ContinueOnError)
	var dbPath, id string
	fs.StringVar(&dbPath, "db", defaultDBPath(), "sqlite db path")
	fs.StringVar(&id, "id", "", "key id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "missing --id")
		return 2
	}

	store, code := openSQLiteStoreOrExit(dbPath)
	if code != 0 {
		return code
	}
	defer func() { _ = store.Close() }()

	if err := store.RevokeAPIKey(ctx, id); err != nil {
		fmt.Fprintln(os.Stderr, "revoke key:", err)
		return 1
	}
	fmt.Println("revoked:", id)
	return 0
}

func defaultDBPath() string {
	return envOr("EXPOSE_DB_PATH", "./expose.db")
}

func openSQLiteStoreOrExit(dbPath string) (*sqlite.Store, int) {
	store, err := sqlite.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		return nil, 1
	}
	return store, 0
}

func runAPIKeySetLimit(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("apikey-set-limit", flag.ContinueOnError)
	var dbPath, id string
	var tunnelLimit int
	fs.StringVar(&dbPath, "db", defaultDBPath(), "sqlite db path")
	fs.StringVar(&id, "id", "", "key id")
	fs.IntVar(&tunnelLimit, "tunnel-limit", -1, "max active tunnels for this key (-1 = unlimited)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "missing --id")
		return 2
	}

	store, code := openSQLiteStoreOrExit(dbPath)
	if code != 0 {
		return code
	}
	defer func() { _ = store.Close() }()

	if err := store.SetAPIKeyTunnelLimit(ctx, id, tunnelLimit); err != nil {
		fmt.Fprintln(os.Stderr, "set tunnel limit:", err)
		return 1
	}
	fmt.Printf("updated key %s: tunnel_limit=%s\n", id, formatTunnelLimit(tunnelLimit))
	return 0
}

func formatTunnelLimit(limit int) string {
	if limit < 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", limit)
}
