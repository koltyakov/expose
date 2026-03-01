package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/client/settings"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/debughttp"
	ilog "github.com/koltyakov/expose/internal/log"
)

func runUp(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "init" {
		return runUpInit(ctx, args[1:])
	}

	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	configFile := "expose.yml"
	fs.StringVar(&configFile, "f", configFile, "Path to expose YAML config")
	fs.StringVar(&configFile, "file", configFile, "Path to expose YAML config")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "up command error:", err)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: expose up [-f expose.yml]")
		return 2
	}

	return runUpFromFile(ctx, configFile)
}

func runUpInit(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("up-init", flag.ContinueOnError)
	configFile := "expose.yml"
	fs.StringVar(&configFile, "f", configFile, "Path to expose YAML config")
	fs.StringVar(&configFile, "file", configFile, "Path to expose YAML config")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "up init error:", err)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: expose up init [-f expose.yml]")
		return 2
	}
	if !isInteractiveInput() {
		fmt.Fprintln(os.Stderr, "up init error: interactive terminal required")
		return 2
	}
	if err := runUpInitInteractive(ctx, os.Stdin, os.Stdout, configFile); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "up init canceled")
			return 130
		}
		fmt.Fprintln(os.Stderr, "up init error:", err)
		return 1
	}
	return 0
}

func runUpFromFile(ctx context.Context, path string) int {
	loadClientEnvFromDotEnv(".env")

	cfg, err := loadUpConfigFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "up config error:", err)
		return 2
	}

	resolvedAccess, err := resolveUpAccess(cfg.Access)
	if err != nil {
		fmt.Fprintln(os.Stderr, "up config error:", err)
		return 2
	}
	cfg.Access = resolvedAccess

	hostRoutes := map[string][]upLocalRoute{}
	for _, t := range cfg.Tunnels {
		hostRoutes[t.Subdomain] = append(hostRoutes[t.Subdomain], upLocalRoute{
			Name:        t.Name,
			Subdomain:   t.Subdomain,
			PathPrefix:  t.PathPrefix,
			StripPrefix: t.StripPrefix,
			LocalPort:   t.Port,
		})
	}

	subdomains := make([]string, 0, len(hostRoutes))
	for sub := range hostRoutes {
		subdomains = append(subdomains, sub)
	}
	sort.Strings(subdomains)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := debughttp.StartPprofServer(runCtx, strings.TrimSpace(envOr("EXPOSE_PPROF_LISTEN", "")), ilog.New("info"), "client"); err != nil {
		fmt.Fprintln(os.Stderr, "up config error: pprof:", err)
		return 2
	}

	interactiveDashboard := isInteractiveOutput()
	var ui *upDashboard
	if interactiveDashboard {
		ui = newUpDashboard(path, Version)
		ui.InitGroups(subdomains, hostRoutes, cfg.Access.Protect)
		ui.Start(runCtx)
		defer ui.Cleanup()
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "Expose Up (%s)\n", path)
		printUpRouteSummary(os.Stdout, cfg)
	}

	type hostClient struct {
		subdomain  string
		routes     []upLocalRoute
		router     *upLocalRouter
		routerPort int
		client     *client.Client
		logger     *slog.Logger
	}

	clients := make([]hostClient, 0, len(subdomains))
	for _, sub := range subdomains {
		var baseLog *slog.Logger
		if ui != nil {
			baseLog = ui.Logger(sub)
			ui.SetGroupStatus(sub, "starting", "starting local router")
		} else {
			baseLog = ilog.New("info").With("group", sub)
		}
		router, routerPort, err := startUpLocalRouter(runCtx, hostRoutes[sub], baseLog)
		if err != nil {
			fmt.Fprintln(os.Stderr, "up error:", err)
			cancel()
			return 1
		}
		if ui != nil {
			ui.SetGroupStatus(sub, "starting", fmt.Sprintf("local router listening on 127.0.0.1:%d", routerPort))
		}

		clientCfg, err := config.ParseClientFlags([]string{"--port", strconv.Itoa(routerPort), "--domain", sub})
		if err != nil {
			fmt.Fprintln(os.Stderr, "up config error:", err)
			cancel()
			return 2
		}
		if cfg.Server != "" {
			clientCfg.ServerURL = cfg.Server
		}
		if cfg.APIKey != "" {
			clientCfg.APIKey = cfg.APIKey
		}
		clientCfg.Protect = cfg.Access.Protect
		clientCfg.User = cfg.Access.User
		clientCfg.Password = cfg.Access.Password

		if err := mergeClientSettings(&clientCfg); err != nil {
			fmt.Fprintln(os.Stderr, "up config error:", err)
			cancel()
			return 2
		}

		c := client.New(clientCfg, nil)
		c.SetVersion(Version)
		c.SetLogger(baseLog)
		clients = append(clients, hostClient{
			subdomain:  sub,
			routes:     hostRoutes[sub],
			router:     router,
			routerPort: routerPort,
			client:     c,
			logger:     baseLog,
		})
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(clients))
	for _, hc := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := hc.client.Run(runCtx)
			if ui != nil {
				if runCtx.Err() != nil && err == nil {
					ui.SetGroupStopped(hc.subdomain, nil)
				} else {
					ui.SetGroupStopped(hc.subdomain, err)
				}
			}
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", hc.subdomain, err)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(errCh)
	}()

	var firstErr error
	for err := range errCh {
		if err == nil {
			continue
		}
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		fmt.Fprintln(os.Stderr, "up error:", err)
	}
	if firstErr != nil {
		return 1
	}
	return 0
}

func resolveUpAccess(access upAccessConfig) (upAccessConfig, error) {
	access.User = strings.TrimSpace(access.User)
	if access.User == "" {
		access.User = "admin"
	}
	access.Password = strings.TrimSpace(access.Password)
	access.PasswordEnv = strings.TrimSpace(access.PasswordEnv)
	explicitPasswordConfigured := access.Password != "" || access.PasswordEnv != ""
	if access.Password != "" && access.PasswordEnv != "" {
		return access, errors.New("protect.password and protect.password_env are mutually exclusive")
	}
	if access.PasswordEnv != "" {
		// Backward-compat: treat protect.password_env as alias for protect.password.
		access.Password = access.PasswordEnv
		access.PasswordEnv = ""
	}
	if looksLikeEnvVarName(access.Password) {
		if v, ok := os.LookupEnv(access.Password); ok {
			access.Password = strings.TrimSpace(v)
		}
	}
	if access.Password != "" {
		access.Protect = true
	}
	if access.Protect && access.Password == "" && !explicitPasswordConfigured {
		if v := strings.TrimSpace(os.Getenv("EXPOSE_PASSWORD")); v != "" {
			access.Password = v
		}
	}
	if access.Protect && access.Password == "" {
		if !isInteractiveInput() {
			return access, errors.New("protect is configured but no password is available (set protect.password or EXPOSE_PASSWORD)")
		}
		pw, err := promptSecret("Public password for all routes (required): ")
		if err != nil {
			return access, err
		}
		access.Password = strings.TrimSpace(pw)
		if access.Password == "" {
			return access, errors.New("password is required when protect is configured")
		}
	}
	return access, nil
}

func looksLikeEnvVarName(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_':
		default:
			return false
		}
	}
	return true
}

func printUpRouteSummary(out io.Writer, cfg upConfig) {
	routes := append([]upTunnelConfig(nil), cfg.Tunnels...)
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].Subdomain == routes[j].Subdomain {
			if routes[i].PathPrefix == routes[j].PathPrefix {
				return routes[i].Name < routes[j].Name
			}
			return routes[i].PathPrefix < routes[j].PathPrefix
		}
		return routes[i].Subdomain < routes[j].Subdomain
	})
	_, _ = fmt.Fprintf(out, "Routes: %d (tunnels by subdomain: %d)\n", len(routes), countDistinctSubdomains(routes))
	for _, r := range routes {
		strip := ""
		if r.StripPrefix {
			strip = " strip"
		}
		protected := ""
		if cfg.Access.Protect {
			protected = " protect"
		}
		_, _ = fmt.Fprintf(out, "  %-12s %s%s -> http://127.0.0.1:%d%s%s\n", r.Name, r.Subdomain, r.PathPrefix, r.Port, protected, strip)
	}
}

func countDistinctSubdomains(routes []upTunnelConfig) int {
	seen := map[string]struct{}{}
	for _, r := range routes {
		seen[r.Subdomain] = struct{}{}
	}
	return len(seen)
}

func runUpInitInteractive(ctx context.Context, in io.Reader, out io.Writer, defaultPath string) error {
	reader := bufio.NewReader(in)
	ui := newWizardTUI()

	ui.printBanner(out,
		"Expose Up Init",
		"Creates an expose.yml project config for multi-route tunnels.",
	)

	cfgPath, err := askWizardValue(ctx, reader, out,
		"Config file path",
		"YAML file to create or overwrite.",
		"Example: ./expose.yml",
		defaultPath,
		strings.TrimSpace,
		validateWizardNonEmpty,
	)
	if err != nil {
		return err
	}

	cfg := upConfig{
		Version: 1,
		Access: upAccessConfig{
			User: "admin",
		},
	}

	includeCreds, err := askWizardYesNo(ctx, reader, out,
		"Store server/API key in expose.yml",
		"If no, `expose up` will use credentials from `expose login` (recommended).",
		false,
	)
	if err != nil {
		return err
	}
	if includeCreds {
		stored, _ := settings.Load()
		serverVal, err := askWizardValue(ctx, reader, out,
			"Server URL",
			"Public server URL for tunnel registration.",
			"Example: https://example.com",
			strings.TrimSpace(stored.ServerURL),
			strings.TrimSpace,
			validateUpServerURLWizard,
		)
		if err != nil {
			return err
		}
		apiKeyVal, err := askWizardValue(ctx, reader, out,
			"API key",
			"Tunnel client API key. Stored in plain text YAML if you continue.",
			"Press Enter to accept existing saved key, if any.",
			strings.TrimSpace(stored.APIKey),
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}
		cfg.Server = serverVal
		cfg.APIKey = apiKeyVal
	}

	protectAll, err := askWizardYesNo(ctx, reader, out,
		"Protect all routes with an access form",
		"Applies the same password gate to every tunnel started by this config.",
		false,
	)
	if err != nil {
		return err
	}
	cfg.Access.Protect = protectAll
	if protectAll {
		user, err := askWizardValue(ctx, reader, out,
			"Auth user",
			"Username required by the access form.",
			"Default: admin",
			"admin",
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}
		cfg.Access.User = user

		passwordValue, err := askWizardValue(ctx, reader, out,
			"Shared password (or env var name)",
			"Store a literal password or an uppercase env var name (example: EXPOSE_PASSWORD).",
			"If the value is uppercase and that env var exists at runtime, `expose up` uses the env value.",
			"EXPOSE_PASSWORD",
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}
		cfg.Access.Password = passwordValue
	}

	cfg.Tunnels = make([]upTunnelConfig, 0, 2)
	for i := 0; ; i++ {
		ui.printSection(out, fmt.Sprintf("Route %d", i+1))
		_, _ = fmt.Fprintln(out)
		name, err := askWizardValue(ctx, reader, out,
			"Route name",
			"Identifier used in logs and summaries.",
			"",
			"",
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}

		subdomain, err := askWizardValue(ctx, reader, out,
			"Subdomain",
			"Public host label under your expose server base domain.",
			"Example: myapp (public URL becomes https://myapp.<base-domain>)",
			"",
			normalizeUpSubdomain,
			validateUpSubdomainWizard,
		)
		if err != nil {
			return err
		}

		portDef := "3000"
		if i == 1 {
			portDef = "8080"
		}
		portStr, err := askWizardValue(ctx, reader, out,
			"Local port",
			"HTTP service port on localhost.",
			"",
			portDef,
			strings.TrimSpace,
			validateUpPortWizard,
		)
		if err != nil {
			return err
		}
		port, _ := strconv.Atoi(portStr)

		pathDef := "/"
		if i == 1 {
			pathDef = "/api"
		}
		pathPrefix, err := askWizardValue(ctx, reader, out,
			"Path prefix",
			"Public path mounted for this route. Longest prefix wins.",
			"",
			pathDef,
			strings.TrimSpace,
			validateUpPathPrefixWizard,
		)
		if err != nil {
			return err
		}

		stripPrefix := false
		normalizedPrefix := strings.TrimSpace(pathPrefix)
		if normalizedPrefix != "" && normalizedPrefix != "/" {
			stripPrefix, err = askWizardYesNo(ctx, reader, out,
				"Strip path prefix before forwarding",
				"Use true when the upstream expects routes at `/` instead of the mounted prefix.",
				pathDef != "/",
			)
			if err != nil {
				return err
			}
		}

		cfg.Tunnels = append(cfg.Tunnels, upTunnelConfig{
			Name:        name,
			Subdomain:   subdomain,
			Port:        port,
			PathPrefix:  pathPrefix,
			StripPrefix: stripPrefix,
		})

		addAnother, err := askWizardYesNo(ctx, reader, out,
			"Add another route",
			"Configure one more host/path mapping.",
			false,
		)
		if err != nil {
			return err
		}
		if !addAnother {
			break
		}
	}

	if _, err := os.Stat(cfgPath); err == nil {
		overwrite, err := askWizardYesNo(ctx, reader, out,
			"Overwrite existing file",
			fmt.Sprintf("%s already exists.", cfgPath),
			false,
		)
		if err != nil {
			return err
		}
		if !overwrite {
			return errors.New("aborted without writing file")
		}
	}

	if err := writeUpConfigFile(cfgPath, cfg); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "%s Saved: %s\n", ui.ok("✓"), cfgPath)
	_, _ = fmt.Fprintln(out)
	ui.printSection(out, "Next")
	_, _ = fmt.Fprintln(out, "  1) expose login   (if server/api key are not stored in expose.yml)")
	_, _ = fmt.Fprintf(out, "     %s\n", ui.cmd("expose login"))
	_, _ = fmt.Fprintln(out, "  2) Start all routes")
	_, _ = fmt.Fprintf(out, "     %s\n", ui.cmd("expose up"))
	return nil
}

func validateUpPortWizard(v string) error {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 || n > 65535 {
		return errors.New("must be a port number (1..65535)")
	}
	return nil
}

func validateUpPathPrefixWizard(v string) error {
	_, err := normalizeUpPathPrefix(v)
	return err
}

func validateUpSubdomainWizard(v string) error {
	v = normalizeUpSubdomain(v)
	if v == "" {
		return errors.New("subdomain is required")
	}
	if strings.Contains(v, "/") || strings.Contains(v, "://") {
		return errors.New("enter a subdomain label, not a URL")
	}
	return nil
}

func validateUpServerURLWizard(v string) error {
	_, err := normalizeServerURL(v)
	return err
}
