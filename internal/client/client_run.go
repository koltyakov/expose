package client

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"time"

	"github.com/koltyakov/expose/internal/versionutil"
)

func (c *Client) Run(ctx context.Context) error {
	localBase, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", c.cfg.LocalPort))
	if err != nil {
		return fmt.Errorf("invalid local URL: %w", err)
	}

	// Auto-update: periodic background check + server-version-change trigger.
	autoUpdateCh := make(chan struct{}, 1) // signals that the binary was replaced
	var lastServerVersion string
	if c.autoUpdate && !isNonReleaseVersion(c.version) {
		go c.runAutoUpdateLoop(ctx, autoUpdateCh)
	}

	backoff := reconnectInitialDelay
	tlsProvisioningRetries := 0
	for {
		reg, err := c.register(ctx)
		if err != nil {
			if isNonRetriableRegisterError(err) {
				return err
			}
			if isTLSProvisioningInProgressError(err) {
				tlsProvisioningRetries++
				if tlsProvisioningRetries <= tlsProvisioningInfoRetries {
					if c.display != nil {
						c.display.ShowInfo(fmt.Sprintf("TLS certificate provisioning in progress; retrying in %s", backoff.Round(time.Second)))
					} else {
						c.log.Info("server TLS certificate provisioning in progress; retrying", "err", err, "retry_in", backoff.Round(time.Second).String())
					}
				} else {
					if c.display != nil {
						c.display.ShowWarning(fmt.Sprintf("tunnel register failed, %s; retrying in %s", shortenError(err), backoff.Round(time.Second)))
					} else {
						c.log.Warn("tunnel register failed while waiting for TLS certificate provisioning", "err", err, "retry_in", backoff.Round(time.Second).String())
					}
				}
			} else {
				tlsProvisioningRetries = 0
				if c.display != nil {
					c.display.ShowWarning(fmt.Sprintf("tunnel register failed, %s; retrying in %s", shortenError(err), backoff.Round(time.Second)))
				} else {
					c.log.Warn("tunnel register failed", "err", err, "retry_in", backoff.Round(time.Second).String())
				}
			}
			select {
			case <-ctx.Done():
				return nil
			case <-autoUpdateCh:
				return ErrAutoUpdated
			case <-time.After(backoff):
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = reconnectInitialDelay
		tlsProvisioningRetries = 0
		if c.display != nil {
			c.display.ShowBanner(c.version)
			localAddr := fmt.Sprintf("http://localhost:%d", c.cfg.LocalPort)
			c.display.ShowTunnelInfo(reg.PublicURL, localAddr, reg.ServerTLSMode, reg.TunnelID)
			c.display.ShowVersions(c.version, versionutil.EnsureVPrefix(reg.ServerVersion), reg.WAFEnabled)
		} else {
			c.log.Info("tunnel ready", "public_url", reg.PublicURL, "tunnel_id", reg.TunnelID)
			if reg.ServerTLSMode != "" {
				c.log.Info("server tls mode", "mode", reg.ServerTLSMode)
			}
			if reg.ServerVersion != "" {
				c.log.Info("versions", "client", c.version, "server", versionutil.EnsureVPrefix(reg.ServerVersion), "waf_enabled", reg.WAFEnabled)
			}
		}

		// Check for updates in the background (non-blocking).
		if !isNonReleaseVersion(c.version) {
			// If server version changed since last registration and auto-update
			// is on, immediately try to self-update.
			if c.autoUpdate && lastServerVersion != "" && reg.ServerVersion != "" &&
				reg.ServerVersion != lastServerVersion {
				c.log.Info("server version changed", "from", lastServerVersion, "to", reg.ServerVersion)
				if c.trySelfUpdate(ctx) {
					return ErrAutoUpdated
				}
			}
			lastServerVersion = reg.ServerVersion
			go c.checkForUpdates(ctx)
		}

		// Check if the background auto-update loop applied an update.
		select {
		case <-autoUpdateCh:
			return ErrAutoUpdated
		default:
		}

		err = c.runSession(ctx, localBase, reg)
		if ctx.Err() != nil {
			return nil
		}
		if c.display != nil {
			reason := "unknown"
			if err != nil {
				reason = err.Error()
			}
			c.display.ShowReconnecting(reason)
		} else {
			c.log.Warn("client disconnected; reconnecting", "err", err, "retry_in", reconnectInitialDelay.Round(time.Second).String())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-autoUpdateCh:
			return ErrAutoUpdated
		case <-time.After(reconnectInitialDelay):
		}
	}
}

func (c *Client) runSession(ctx context.Context, localBase *url.URL, reg registerResponse) error {
	rt, err := newClientSessionRuntime(c, ctx, localBase, reg)
	if err != nil {
		return err
	}
	defer rt.close()
	return rt.run()
}

func nextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		current = reconnectInitialDelay
	}
	next := min(current*2, reconnectMaxDelay)
	// Add ±25% jitter to avoid thundering herd on reconnect.
	jitter := 1.0 + (rand.Float64()-0.5)*0.5 // range [0.75, 1.25]
	return time.Duration(float64(next) * jitter)
}
