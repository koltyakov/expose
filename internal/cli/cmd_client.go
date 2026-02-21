package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/clientsettings"
	"github.com/koltyakov/expose/internal/config"
	ilog "github.com/koltyakov/expose/internal/log"
)

func runHTTP(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	serverURL := envOr("EXPOSE_DOMAIN", "")
	apiKey := envOr("EXPOSE_API_KEY", "")
	name := ""
	protect := false
	port := parseIntEnv("EXPOSE_PORT", 0)
	fs.IntVar(&port, "port", port, "Local HTTP port on 127.0.0.1")
	fs.StringVar(&name, "domain", name, "Requested public subdomain (e.g. myapp)")
	fs.BoolVar(&protect, "protect", protect, "Protect this tunnel with a password challenge")
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
	clientArgs = appendFlagIfNotEmpty(clientArgs, "--domain", name)
	clientArgs = appendFlagIfNotEmpty(clientArgs, "--server", serverURL)
	clientArgs = appendFlagIfNotEmpty(clientArgs, "--api-key", apiKey)
	if protect {
		clientArgs = append(clientArgs, "--protect")
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
	var missing bool
	serverURL, missing, err := resolveRequiredValue(reader, serverURL, canPrompt, "Server host or URL: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "client login error:", err)
		return 1
	}
	if missing {
		fmt.Fprintln(os.Stderr, "client login error: missing --server (or EXPOSE_DOMAIN)")
		return 2
	}

	apiKey, missing, err = resolveRequiredValue(reader, apiKey, canPrompt, "API key: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "client login error:", err)
		return 1
	}
	if missing {
		fmt.Fprintln(os.Stderr, "client login error: missing --api-key (or EXPOSE_API_KEY)")
		return 2
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
	loadClientEnvFromDotEnv(".env")

	cfg, err := config.ParseClientFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}
	if err := mergeClientSettings(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}
	if err := promptClientPasswordIfNeeded(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}

	var logger *slog.Logger
	c := client.New(cfg, nil) // logger set below
	c.SetVersion(Version)

	if isInteractiveOutput() {
		display := client.NewDisplay(true)
		defer display.Cleanup()
		c.SetDisplay(display)
		logger = ilog.NewStderr("warn")
	} else {
		logger = ilog.New("info")
	}
	c.SetLogger(logger)

	// Auto-update on start when EXPOSE_AUTOUPDATE=true.
	if isAutoUpdateEnabled() {
		if autoUpdateOnStart(ctx, Version, logger) {
			return restartProcess(logger)
		}
		c.SetAutoUpdate(true)
	}

	if err := c.Run(ctx); err != nil {
		if errors.Is(err, client.ErrAutoUpdated) {
			return restartProcess(logger)
		}
		fmt.Fprintln(os.Stderr, "client error:", err)
		return 1
	}
	return 0
}

func mergeClientSettings(cfg *config.ClientConfig) error {
	hasInlineCreds := hasNonEmpty(cfg.ServerURL) && hasNonEmpty(cfg.APIKey)
	if !hasInlineCreds {
		stored, err := clientsettings.Load()
		if err != nil {
			return missingClientCredentialsError(err)
		}
		if !hasNonEmpty(cfg.ServerURL) {
			cfg.ServerURL = stored.ServerURL
		}
		if !hasNonEmpty(cfg.APIKey) {
			cfg.APIKey = stored.APIKey
		}
		if !hasNonEmpty(cfg.ServerURL) || !hasNonEmpty(cfg.APIKey) {
			return missingClientCredentialsError(nil)
		}
	}
	normalized, err := normalizeServerURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	cfg.ServerURL = normalized
	return nil
}

func hasNonEmpty(v string) bool {
	return strings.TrimSpace(v) != ""
}

func missingClientCredentialsError(cause error) error {
	const message = "missing client credentials. run `expose login --server https://example.com --api-key <key>` or provide --server/--api-key"
	if cause == nil {
		return errors.New(message)
	}
	return fmt.Errorf("%s: %w", message, cause)
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
