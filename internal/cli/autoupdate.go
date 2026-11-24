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

var autoUpdateCheckAndApply = selfupdate.CheckAndApply
var autoUpdateSupported = selfupdate.Supported

// isAutoUpdateEnabled reports whether the EXPOSE_AUTOUPDATE environment
// variable is set to a truthy value (true, 1, yes).
func isAutoUpdateEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("EXPOSE_AUTOUPDATE")))
	return v == "true" || v == "1" || v == "yes"
}

// autoUpdateActive reports whether EXPOSE_AUTOUPDATE is enabled and this
// build can verify release signatures. Builds without pinned release keys are
// reported once instead of failing every periodic check.
func autoUpdateActive(logger *slog.Logger) bool {
	if !isAutoUpdateEnabled() {
		return false
	}
	if err := autoUpdateSupported(); err != nil {
		logger.Warn("auto-update: disabled; this build cannot verify release signatures", "err", err)
		return false
	}
	return true
}

// autoUpdateStartedByUpdate reports whether an update restart started this
// process; its startup check is then skipped.
var autoUpdateStartedByUpdate = selfupdate.StartedByUpdate

// startAutoUpdateLoop runs startup, periodic and client-triggered update
// checks. The caller runs it beside the service it updates, so a slow or
// unreachable release API never delays startup. checkAtStart requests an
// immediate first check. When an update is successfully applied it calls
// onUpdate (which should trigger a graceful shutdown) and returns.
func startAutoUpdateLoop(ctx context.Context, currentVersion string, logger *slog.Logger, checkAtStart bool, updateChecks <-chan struct{}, onUpdate func()) {
	if currentVersion == "" {
		return
	}
	logger.Info("auto-update: periodic checks enabled", "interval", autoUpdateCheckInterval)
	ticker := time.NewTicker(autoUpdateCheckInterval)
	defer ticker.Stop()
	for first := true; ; first = false {
		if first && checkAtStart {
			logger.Info("auto-update: checking for updates", "current_version", currentVersion)
		} else {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-updateChecks:
				logger.Info("auto-update: newer client registered, checking for updates")
			}
		}
		if ctx.Err() != nil {
			return
		}
		result, err := autoUpdateCheckAndApply(ctx, currentVersion)
		if err != nil {
			logger.Warn("auto-update: check failed", "err", err)
			continue
		}
		if result.Updated {
			logger.Info("auto-update: update applied", "from", result.CurrentVersion, "to", versionutil.EnsureVPrefix(result.LatestVersion))
			onUpdate()
			return
		}
		logger.Debug("auto-update: check passed, up to date")
	}
}

// restartProcess replaces the process on Unix. Windows launches a replacement
// that waits for this process to exit, so success must return exit code zero.
func restartProcess(logger *slog.Logger) int {
	logger.Info("auto-update: restarting process")
	if err := selfupdate.Restart(); err != nil {
		fmt.Fprintln(os.Stderr, "auto-update: restart failed:", err)
		return 1
	}
	return 0
}
