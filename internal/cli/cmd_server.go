package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/koltyakov/expose/internal/config"
	ilog "github.com/koltyakov/expose/internal/log"
	"github.com/koltyakov/expose/internal/server"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

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
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			if id := parseDarwinIOPlatformUUID(string(out)); id != "" {
				return id
			}
		}
		if out, err := exec.Command("sysctl", "-n", "kern.uuid").Output(); err == nil {
			if id := strings.TrimSpace(string(out)); id != "" {
				return id
			}
		}
	}
	return ""
}

func parseDarwinIOPlatformUUID(raw string) string {
	const marker = `"IOPlatformUUID" = "`
	idx := strings.Index(raw, marker)
	if idx < 0 {
		return ""
	}
	start := idx + len(marker)
	end := strings.Index(raw[start:], `"`)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(raw[start : start+end])
}
