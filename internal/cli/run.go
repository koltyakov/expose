// Package cli implements the expose command-line interface, dispatching
// subcommands for server, client, login, and API key administration.
package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/clientsettings"
	"github.com/koltyakov/expose/internal/config"
	ilog "github.com/koltyakov/expose/internal/log"
	"github.com/koltyakov/expose/internal/server"
	"github.com/koltyakov/expose/internal/store/sqlite"
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
	case "tunnel":
		return runTunnel(ctx, args[1:])
	case "client":
		return runClientCommand(ctx, args[1:])
	case "server":
		return runServer(ctx, args[1:])
	case "apikey":
		return runAPIKeyAdmin(ctx, args[1:])
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

func runHTTP(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	serverURL := envOr("EXPOSE_DOMAIN", "")
	apiKey := envOr("EXPOSE_API_KEY", "")
	name := ""
	port := parseIntEnv("EXPOSE_PORT", 0)
	fs.IntVar(&port, "port", port, "Local HTTP port on 127.0.0.1")
	fs.StringVar(&name, "domain", name, "Requested public subdomain (e.g. myapp)")
	fs.StringVar(&serverURL, "server", serverURL, "Server URL (e.g. https://example.com)")
	fs.StringVar(&apiKey, "api-key", apiKey, "API key")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "http command error:", err)
		return 2
	}

	rest := fs.Args()
	if len(rest) > 1 {
		fmt.Fprintln(os.Stderr, "http command error: expected a single port, e.g. `expose http 3000`")
		return 2
	}
	if len(rest) == 1 {
		p, err := strconv.Atoi(strings.TrimSpace(rest[0]))
		if err != nil {
			fmt.Fprintln(os.Stderr, "http command error: invalid port:", rest[0])
			return 2
		}
		port = p
	}
	if port <= 0 || port > 65535 {
		fmt.Fprintln(os.Stderr, "http command error: missing or invalid port (1..65535)")
		return 2
	}

	clientArgs := []string{"--port", strconv.Itoa(port)}
	name = strings.TrimSpace(name)
	if name != "" {
		clientArgs = append(clientArgs, "--domain", name)
	}
	serverURL = strings.TrimSpace(serverURL)
	if serverURL != "" {
		clientArgs = append(clientArgs, "--server", serverURL)
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey != "" {
		clientArgs = append(clientArgs, "--api-key", apiKey)
	}
	return runClient(ctx, clientArgs)
}

func runTunnel(ctx context.Context, args []string) int {
	return runClient(ctx, args)
}

func runClientLogin(args []string) int {
	fs := flag.NewFlagSet("client-login", flag.ContinueOnError)
	serverURL := envOr("EXPOSE_DOMAIN", "")
	apiKey := envOr("EXPOSE_API_KEY", "")
	fs.StringVar(&serverURL, "server", serverURL, "Server URL (e.g. https://example.com)")
	fs.StringVar(&apiKey, "api-key", apiKey, "API key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	serverURL = strings.TrimSpace(serverURL)
	apiKey = strings.TrimSpace(apiKey)
	canPrompt := isInteractiveInput()
	reader := bufio.NewReader(os.Stdin)
	if serverURL == "" {
		if !canPrompt {
			fmt.Fprintln(os.Stderr, "client login error: missing --server (or EXPOSE_DOMAIN)")
			return 2
		}
		v, err := prompt(reader, "Server host or URL: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "client login error:", err)
			return 1
		}
		serverURL = v
	}
	if apiKey == "" {
		if !canPrompt {
			fmt.Fprintln(os.Stderr, "client login error: missing --api-key (or EXPOSE_API_KEY)")
			return 2
		}
		v, err := prompt(reader, "API key: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "client login error:", err)
			return 1
		}
		apiKey = v
	}
	if serverURL == "" || apiKey == "" {
		fmt.Fprintln(os.Stderr, "client login error: server and api key are required")
		return 2
	}
	normalizedServerURL, err := normalizeServerURL(serverURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client login error:", err)
		return 2
	}
	if err := clientsettings.Save(clientsettings.Settings{
		ServerURL: normalizedServerURL,
		APIKey:    apiKey,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "client login error:", err)
		return 1
	}
	fmt.Println("saved:", clientsettings.Path())
	return 0
}

func runClient(ctx context.Context, args []string) int {
	cfg, err := config.ParseClientFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}
	if err := mergeClientSettings(&cfg); err != nil {
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

func mergeClientSettings(cfg *config.ClientConfig) error {
	if strings.TrimSpace(cfg.ServerURL) != "" && strings.TrimSpace(cfg.APIKey) != "" {
		return nil
	}
	stored, err := clientsettings.Load()
	if err != nil {
		return fmt.Errorf("missing client credentials. run `expose login --server https://example.com --api-key <key>` or provide --server/--api-key: %w", err)
	}
	if strings.TrimSpace(cfg.ServerURL) == "" {
		cfg.ServerURL = stored.ServerURL
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		cfg.APIKey = stored.APIKey
	}
	if strings.TrimSpace(cfg.ServerURL) == "" || strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("missing client credentials. run `expose login --server https://example.com --api-key <key>` or provide --server/--api-key")
	}
	normalized, err := normalizeServerURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	cfg.ServerURL = normalized
	return nil
}

func runServer(ctx context.Context, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "apikey":
			return runAPIKeyAdmin(ctx, args[1:])
		case "wizard":
			return runServerWizard(ctx, args[1:])
		}
	}

	loadServerEnvFromDotEnv(".env")

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
	defer func() { _ = store.Close() }()

	pepper, err := resolveServerPepper(ctx, store, cfg.APIKeyPepper)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server config error:", err)
		return 2
	}
	cfg.APIKeyPepper = pepper

	s := server.New(cfg, store, logger)
	if err := s.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		return 1
	}
	return 0
}

func loadServerEnvFromDotEnv(path string) {
	values := loadEnvFileValues(path)
	for key, value := range values {
		if !strings.HasPrefix(key, "EXPOSE_") {
			continue
		}
		if existing := strings.TrimSpace(os.Getenv(key)); existing != "" {
			continue
		}
		_ = os.Setenv(key, value)
	}
}

func runAPIKeyAdmin(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: expose apikey <create|list|revoke> [flags]")
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
	fs.StringVar(&pepper, "api-key-pepper", envOr("EXPOSE_API_KEY_PEPPER", ""), "hash pepper override")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db error:", err)
		return 1
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
	defer func() { _ = store.Close() }()

	if err := store.RevokeAPIKey(ctx, id); err != nil {
		fmt.Fprintln(os.Stderr, "revoke key:", err)
		return 1
	}
	fmt.Println("revoked:", id)
	return 0
}

func printUsage() {
	fmt.Println(`expose - Bring Your Own Infrastructure (BYOI) HTTP tunnel

Expose local HTTP ports to the internet through your own server.

Usage:
  expose http <port>                    Expose local port (temporary subdomain)
  expose http --domain=myapp <port>     Expose with a named subdomain
  expose login                          Save server URL and API key
  expose server                         Start tunnel server
  expose server wizard                  Guided server setup + .env write
  expose apikey create --name NAME      Create a new API key
  expose apikey list                    List all API keys
  expose apikey revoke --id=ID          Revoke an API key
  expose version                        Print version
  expose help                           Show this help

Quick Start:
  1. expose server                                 # start server
  2. expose apikey create --name default            # create API key
  3. expose login --server example.com --api-key KEY  # save credentials
  4. expose http 3000                               # expose local port

Environment Variables:
  EXPOSE_DOMAIN           Server base domain (e.g. example.com)
  EXPOSE_API_KEY          API key for client authentication
  EXPOSE_PORT             Local port to expose
  EXPOSE_SUBDOMAIN        Requested subdomain name
  EXPOSE_TLS_MODE         TLS mode: auto|dynamic|wildcard (default: auto)
  EXPOSE_DB_PATH          SQLite database path (default: ./expose.db)
  EXPOSE_LOG_LEVEL        Log level: debug|info|warn|error (default: info)

For detailed documentation, see: https://github.com/koltyakov/expose`)
}

// Version is set at build time via -ldflags.
var Version = "dev"

func printVersion() {
	fmt.Println("expose", Version)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseIntEnv(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func normalizeServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("missing server URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", errors.New("server URL must use https")
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", errors.New("server URL must include host")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String(), nil
}

func resolveServerPepper(ctx context.Context, store *sqlite.Store, configured string) (string, error) {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		return store.ResolveServerPepper(ctx, configured)
	}

	current, exists, err := store.GetServerPepper(ctx)
	if err == nil {
		if exists {
			return current, nil
		}
		return store.ResolveServerPepper(ctx, chooseServerPepper())
	}
	return "", err
}

func chooseServerPepper() string {
	machineID := detectMachineID()
	if machineID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("expose-pepper:" + machineID))
	return hex.EncodeToString(sum[:])
}

func detectMachineID() string {
	for _, p := range []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	} {
		if b, err := os.ReadFile(p); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	return ""
}

func isInteractiveInput() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func prompt(reader *bufio.Reader, label string) (string, error) {
	if _, err := fmt.Fprint(os.Stdout, label); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
