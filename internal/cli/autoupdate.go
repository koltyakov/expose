package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/selfupdate"
	"github.com/koltyakov/expose/internal/versionutil"
)

const autoUpdateCheckInterval = 30 * time.Minute

// isAutoUpdateEnabled reports whether the EXPOSE_AUTOUPDATE environment
// variable is set to a truthy value (true, 1, yes).
func isAutoUpdateEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("EXPOSE_AUTOUPDATE")))
	return v == "true" || v == "1" || v == "yes"
}

// autoUpdateOnStart performs a single update check. If a newer release is
// available it downloads and replaces the binary in-place. Returns true
// when the binary was replaced and the caller should restart the process.
func autoUpdateOnStart(ctx context.Context, currentVersion string, logger *slog.Logger) bool {
	if currentVersion == "" || currentVersion == "dev" || strings.HasSuffix(currentVersion, "-dev") {
		return false
	}
	logger.Info("auto-update: checking for updates", "current_version", currentVersion)
	result, err := selfupdate.CheckAndApply(ctx, currentVersion)
	if err != nil {
		logger.Warn("auto-update: check failed", "err", err)
		return false
	}
	if !result.Updated {
		logger.Info("auto-update: already up to date", "version", currentVersion)
		return false
	}
	logger.Info("auto-update: binary replaced", "from", result.CurrentVersion, "to", versionutil.EnsureVPrefix(result.LatestVersion), "asset", result.AssetName)
	return true
}

// startAutoUpdateLoop runs periodic update checks in the background. When
// an update is successfully applied it calls onUpdate (which should trigger
// a graceful shutdown) and returns.
func startAutoUpdateLoop(ctx context.Context, currentVersion string, logger *slog.Logger, onUpdate func()) {
	if currentVersion == "" || currentVersion == "dev" || strings.HasSuffix(currentVersion, "-dev") {
		return
	}
	logger.Info("auto-update: periodic checks enabled", "interval", autoUpdateCheckInterval)
	ticker := time.NewTicker(autoUpdateCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := selfupdate.CheckAndApply(ctx, currentVersion)
			if err != nil {
				logger.Warn("auto-update: periodic check failed", "err", err)
				continue
			}
			if result.Updated {
				logger.Info("auto-update: update applied", "from", result.CurrentVersion, "to", versionutil.EnsureVPrefix(result.LatestVersion))
				onUpdate()
				return
			}
			logger.Debug("auto-update: periodic check passed, up to date")
		}
	}
}

// restartProcess re-executes the current binary. On success syscall.Exec
// replaces the process and this function never returns. On failure it
// logs the error and returns exit code 1.
func restartProcess(logger *slog.Logger) int {
	logger.Info("auto-update: restarting process")
	if err := selfupdate.Restart(); err != nil {
		fmt.Fprintln(os.Stderr, "auto-update: restart failed:", err)
		return 1
	}
	return 0 // unreachable on success
}
