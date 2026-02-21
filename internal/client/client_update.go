package client

import (
	"context"
	"time"

	"github.com/koltyakov/expose/internal/selfupdate"
	"github.com/koltyakov/expose/internal/versionutil"
)

// checkForUpdates queries GitHub for a newer release and displays the result.
func (c *Client) checkForUpdates(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rel, err := selfupdate.Check(checkCtx, c.version)
	if err != nil {
		c.log.Debug("update check failed", "err", err)
		return
	}
	if rel == nil {
		// Already up to date.
		if c.display != nil {
			c.display.ShowUpdateStatus("")
		}
		return
	}
	latest := versionutil.EnsureVPrefix(rel.TagName)
	if c.display != nil {
		c.display.ShowUpdateStatus(latest)
	} else {
		c.log.Info("update available", "latest", latest, "current", c.version, "run", "expose update")
	}
}

const clientAutoUpdateInterval = 30 * time.Minute

// runAutoUpdateLoop periodically checks for a newer release. When an update
// is downloaded and the binary replaced it sends on the channel and returns.
func (c *Client) runAutoUpdateLoop(ctx context.Context, updated chan<- struct{}) {
	c.log.Info("auto-update: periodic checks enabled", "interval", clientAutoUpdateInterval)
	ticker := time.NewTicker(clientAutoUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.trySelfUpdate(ctx) {
				select {
				case updated <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

// trySelfUpdate checks for a newer release and applies it. Returns true
// when the binary was replaced and the process should restart.
func (c *Client) trySelfUpdate(ctx context.Context) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	result, err := selfupdate.CheckAndApply(checkCtx, c.version)
	if err != nil {
		c.log.Warn("auto-update: check failed", "err", err)
		return false
	}
	if !result.Updated {
		c.log.Debug("auto-update: already up to date")
		return false
	}
	c.log.Info("auto-update: binary replaced", "from", result.CurrentVersion, "to", versionutil.EnsureVPrefix(result.LatestVersion), "asset", result.AssetName)
	if c.display != nil {
		c.display.ShowInfo("Update applied (" + versionutil.EnsureVPrefix(result.LatestVersion) + "); restarting...")
	}
	return true
}
