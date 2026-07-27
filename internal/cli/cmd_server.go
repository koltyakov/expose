package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/debughttp"
	ilog "github.com/koltyakov/expose/internal/log"
	"github.com/koltyakov/expose/internal/server"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func runServer(ctx context.Context, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "apikey":
			return runAPIKeyAdmin(ctx, args[1:])
		case "init":
			return runServerInit(ctx, args[1:])
		}
	}

	loadServerEnvFromDotEnv(".env")

	cfg, err := config.ParseServerFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server config error:", err)
		return 2
	}
	logger := ilog.New(cfg.LogLevel)

	// Auto-update on start when EXPOSE_AUTOUPDATE=true.
	if isAutoUpdateEnabled() {
		if autoUpdateOnStart(ctx, Version, logger) {
			return restartProcess(logger)
		}
	}

	store, err := sqlite.OpenWithOptions(cfg.DBPath, sqlite.OpenOptions{
		MaxOpenConns: cfg.DBMaxOpenConns,
		MaxIdleConns: cfg.DBMaxIdleConns,
	})
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

	accessCookieSecret, ephemeralCookieSecret, err := resolveAccessCookieSecret(ctx, store, cfg.AccessCookieSecret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server config error:", err)
		return 2
	}
	cfg.AccessCookieSecret = accessCookieSecret
	if ephemeralCookieSecret {
		logger.Warn("access cookie secret auto-generated for this process; protected-route form sessions will reset on restart", "env", "EXPOSE_ACCESS_COOKIE_SECRET")
	}

	// Create child context so the auto-update loop can trigger graceful shutdown.
	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	var needsRestart atomic.Bool
	if isAutoUpdateEnabled() {
		go startAutoUpdateLoop(serverCtx, Version, logger, func() {
			needsRestart.Store(true)
			serverCancel()
		})
	}

	s := server.New(cfg, store, logger, Version)
	if err := debughttp.StartPprofServer(ctx, cfg.PprofListen, logger, "server", map[string]http.HandlerFunc{
		"/debug/metrics": s.MetricsHandler(),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "server config error: pprof:", err)
		return 2
	}
	if err := s.Run(serverCtx); err != nil {
		if !needsRestart.Load() {
			fmt.Fprintln(os.Stderr, "server error:", err)
			return 1
		}
	}

	if needsRestart.Load() {
		_ = store.Close()
		return restartProcess(logger)
	}
	return 0
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
		generated, genErr := auth.GenerateAPIKey()
		if genErr != nil {
			return "", genErr
		}
		return store.ResolveServerPepper(ctx, generated)
	}
	return "", err
}

// resolveAccessCookieSecret picks the HMAC secret for protected-route access
// cookies: explicit config first, then the secret persisted in server_settings,
// then a freshly generated random secret persisted for future starts. If the
// database cannot be read or written, it falls back to an ephemeral random
// secret (reported via the second return value) so startup never blocks on a
// transient DB failure.
func resolveAccessCookieSecret(ctx context.Context, store *sqlite.Store, configured string) (string, bool, error) {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		return configured, false, nil
	}

	current, exists, err := store.GetAccessCookieSecret(ctx)
	if err != nil {
		generated, genErr := auth.GenerateAPIKey()
		if genErr != nil {
			return "", false, genErr
		}
		return generated, true, nil
	}
	if exists && strings.TrimSpace(current) != "" {
		return current, false, nil
	}

	generated, err := auth.GenerateAPIKey()
	if err != nil {
		return "", false, err
	}
	persisted, err := store.ResolveAccessCookieSecret(ctx, generated)
	if err != nil {
		return generated, true, nil
	}
	return persisted, false, nil
}
