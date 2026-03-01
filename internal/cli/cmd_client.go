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
	"time"

	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/client/settings"
	"github.com/koltyakov/expose/internal/config"
	ilog "github.com/koltyakov/expose/internal/log"
	"github.com/koltyakov/expose/internal/selfupdate"
	"github.com/koltyakov/expose/internal/versionutil"
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
	fs.BoolVar(&protect, "protect", protect, "Protect this tunnel with the built-in access form")
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

func runStatic(ctx context.Context, args []string) int {
	loadClientEnvFromDotEnv(".env")

	fs := flag.NewFlagSet("static", flag.ContinueOnError)
	serverURL := envOr("EXPOSE_DOMAIN", "")
	apiKey := envOr("EXPOSE_API_KEY", "")
	name := ""
	protect := false
	folders := false
	spa := false
	root := "."
	var allowPatterns stringListFlag
	fs.StringVar(&root, "dir", root, "Local directory to serve")
	fs.StringVar(&name, "domain", name, "Requested public subdomain (e.g. myapp)")
	fs.BoolVar(&protect, "protect", protect, "Protect this tunnel with the built-in access form")
	fs.BoolVar(&folders, "folders", folders, "Allow directory listings when no index.html is present")
	fs.BoolVar(&spa, "spa", spa, "Fallback unresolved GET/HEAD routes to /index.html")
	fs.StringVar(&serverURL, "server", serverURL, "Server URL (e.g. https://example.com)")
	fs.StringVar(&apiKey, "api-key", apiKey, "API key")
	fs.Var(&allowPatterns, "allow", "Allow blocked static paths matching a glob pattern (repeatable, e.g. .well-known/**)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "static command error:", err)
		return 2
	}

	rest := fs.Args()
	if len(rest) > 1 {
		fmt.Fprintln(os.Stderr, "static command error: expected at most one directory, e.g. `expose static ./public`")
		return 2
	}
	if len(rest) == 1 {
		root = rest[0]
	}
	absRoot, err := resolveStaticRoot(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "static command error:", err)
		return 2
	}

	cfg := config.ClientConfig{
		ServerURL: serverURL,
		APIKey:    apiKey,
		User:      envOr("EXPOSE_USER", "admin"),
		Password:  envOr("EXPOSE_PASSWORD", ""),
		Protect:   protect,
		Name:      name,
		Timeout:   30 * time.Second,
	}
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.User = strings.TrimSpace(cfg.User)
	if cfg.User == "" {
		cfg.User = "admin"
	}
	if cfg.Name == "" {
		hostname, _ := os.Hostname()
		cfg.Name = defaultStaticSubdomain(client.ResolveMachineID(hostname), absRoot)
	}
	cfg.Password = strings.TrimSpace(cfg.Password)
	cfg.Protect = cfg.Protect || cfg.Password != ""
	if len(cfg.Password) > 256 {
		fmt.Fprintln(os.Stderr, "static command error: password must be at most 256 characters")
		return 2
	}

	if err := mergeClientSettings(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}
	if err := promptClientPasswordIfNeeded(ctx, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}

	staticSrv, port, err := startStaticFileServer(ctx, absRoot, staticServerOptions{
		AllowPatterns: allowPatterns.values(),
		AllowFolders:  folders,
		SPA:           spa,
		Unprotected:   !cfg.Protect,
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "static command error:", err)
		return 2
	}
	defer func() { _ = staticSrv.Close() }()

	cfg.LocalPort = port
	return runConfiguredClient(ctx, cfg)
}

func runTunnel(ctx context.Context, args []string) int {
	return runClient(ctx, args)
}

func runClientLogin(ctx context.Context, args []string) int {
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
	serverURL, missing, err := resolveRequiredValueContext(ctx, reader, serverURL, canPrompt, "Server host or URL: ")
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "client login canceled")
			return 130
		}
		fmt.Fprintln(os.Stderr, "client login error:", err)
		return 1
	}
	if missing {
		fmt.Fprintln(os.Stderr, "client login error: missing --server (or EXPOSE_DOMAIN)")
		return 2
	}

	apiKey, missing, err = resolveRequiredValueContext(ctx, reader, apiKey, canPrompt, "API key: ")
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "client login canceled")
			return 130
		}
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
	if err := settings.Save(settings.Credentials{
		ServerURL: normalizedServerURL,
		APIKey:    apiKey,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "client login error:", err)
		return 1
	}
	fmt.Println("saved:", settings.Path())
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
	if err := promptClientPasswordIfNeeded(ctx, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "client config error:", err)
		return 2
	}
	return runConfiguredClient(ctx, cfg)
}

func runConfiguredClient(ctx context.Context, cfg config.ClientConfig) int {
	var logger *slog.Logger
	var display *client.Display
	displayCleanup := func() {}
	c := client.New(cfg, nil) // logger set below
	c.SetVersion(Version)

	if isInteractiveOutput() {
		display = client.NewDisplay(true)
		cleaned := false
		displayCleanup = func() {
			if cleaned || display == nil {
				return
			}
			cleaned = true
			display.Cleanup()
		}
		defer displayCleanup()
		c.SetDisplay(display)
		logger = ilog.NewStderr("warn")
	} else {
		logger = ilog.New("info")
	}
	c.SetLogger(logger)

	// Auto-update on start when EXPOSE_AUTOUPDATE=true.
	if isAutoUpdateEnabled() {
		if autoUpdateOnStart(ctx, Version, logger) {
			displayCleanup()
			return restartProcess(logger)
		}
		c.SetAutoUpdate(true)
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	hotkeyCleanup := func() {}
	hotkeyCh := (<-chan struct{})(nil)
	if display != nil && isInteractiveInput() {
		ch, cleanup, err := startClientUpdateHotkeyListener()
		if err != nil {
			logger.Debug("client hotkeys disabled", "err", err)
		} else {
			hotkeyCh = ch
			hotkeyCleanup = cleanup
			defer hotkeyCleanup()
		}
	}

	runDone := make(chan error, 1)
	go func() {
		runDone <- c.Run(runCtx)
	}()

	type manualUpdateResult struct {
		result *selfupdate.Result
		err    error
	}
	manualUpdateDone := make(chan manualUpdateResult, 1)
	updateBusy := false
	restartAfterClientExit := false

	for {
		select {
		case err := <-runDone:
			if restartAfterClientExit {
				hotkeyCleanup()
				displayCleanup()
				return restartProcess(logger)
			}
			if errors.Is(err, client.ErrAutoUpdated) {
				hotkeyCleanup()
				displayCleanup()
				return restartProcess(logger)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "client error:", err)
				return 1
			}
			return 0
		case <-hotkeyCh:
			if updateBusy {
				if display != nil {
					display.ShowInfo("Update already in progress...")
				}
				continue
			}
			if Version == "" || Version == "dev" || strings.HasSuffix(Version, "-dev") {
				if display != nil {
					display.ShowWarning("Self-update is unavailable for dev builds")
				}
				continue
			}
			updateBusy = true
			if display != nil {
				display.ShowInfo("Checking for updates...")
			}
			go func() {
				checkCtx, cancel := context.WithTimeout(runCtx, 2*time.Minute)
				defer cancel()
				result, err := selfupdate.CheckAndApply(checkCtx, Version)
				manualUpdateDone <- manualUpdateResult{result: result, err: err}
			}()
		case res := <-manualUpdateDone:
			updateBusy = false
			if res.err != nil {
				msg := "Update failed: " + res.err.Error()
				if display != nil {
					display.ShowWarning(msg)
				}
				logger.Warn("manual update failed", "err", res.err)
				continue
			}
			if res.result == nil || !res.result.Updated {
				if display != nil {
					display.ShowInfo("Already up to date.")
				}
				continue
			}
			latest := versionutil.EnsureVPrefix(res.result.LatestVersion)
			if display != nil {
				display.ShowInfo("Update applied (" + latest + "); restarting...")
			}
			restartAfterClientExit = true
			cancelRun()
		}
	}
}

type stringListFlag struct {
	items []string
}

func (f *stringListFlag) String() string {
	if f == nil || len(f.items) == 0 {
		return ""
	}
	return strings.Join(f.items, ",")
}

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value cannot be empty")
	}
	f.items = append(f.items, value)
	return nil
}

func (f *stringListFlag) values() []string {
	if f == nil || len(f.items) == 0 {
		return nil
	}
	out := make([]string, len(f.items))
	copy(out, f.items)
	return out
}

func mergeClientSettings(cfg *config.ClientConfig) error {
	hasInlineCreds := hasNonEmpty(cfg.ServerURL) && hasNonEmpty(cfg.APIKey)
	if !hasInlineCreds {
		stored, err := settings.Load()
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
