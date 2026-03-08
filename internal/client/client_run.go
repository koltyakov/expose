package client

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/koltyakov/expose/internal/versionutil"
)

type sessionRuntime interface {
	run() error
	close()
	transportKind() string
}

type reconnectSchedule struct {
	startedAt time.Time
}

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

	var retry reconnectSchedule
	tlsProvisioningRetries := 0
	for {
		reg, err := c.register(ctx)
		if err != nil {
			delay := retry.nextDelay(time.Now())
			willRetry := !isNonRetriableRegisterError(err)
			if hook := c.hooks.OnRegisterFailure; hook != nil {
				hook(RegisterFailureEvent{
					Err:       err,
					RetryIn:   delay,
					WillRetry: willRetry,
				})
			}
			if isNonRetriableRegisterError(err) {
				return err
			}
			if isTLSProvisioningInProgressError(err) {
				tlsProvisioningRetries++
				if tlsProvisioningRetries <= tlsProvisioningInfoRetries {
					if c.display != nil {
						c.display.ShowInfo(fmt.Sprintf("TLS certificate provisioning in progress; retrying in %s", delay.Round(time.Second)))
					} else {
						c.log.Info("server TLS certificate provisioning in progress; retrying", "err", err, "retry_in", delay.Round(time.Second).String())
					}
				} else {
					if c.display != nil {
						c.display.ShowWarning(fmt.Sprintf("tunnel register failed, %s; retrying in %s", shortenError(err), delay.Round(time.Second)))
					} else {
						c.log.Warn("tunnel register failed while waiting for TLS certificate provisioning", "err", err, "retry_in", delay.Round(time.Second).String())
					}
				}
			} else {
				tlsProvisioningRetries = 0
				if c.display != nil {
					c.display.ShowWarning(fmt.Sprintf("tunnel register failed, %s; retrying in %s", shortenError(err), delay.Round(time.Second)))
				} else {
					c.log.Warn("tunnel register failed", "err", err, "retry_in", delay.Round(time.Second).String())
				}
			}
			select {
			case <-ctx.Done():
				return nil
			case <-autoUpdateCh:
				return ErrAutoUpdated
			case <-time.After(delay):
			}
			continue
		}
		tlsProvisioningRetries = 0
		c.resumeID = reg.TunnelID

		rt, err := newSessionRuntime(c, ctx, localBase, reg)
		if err != nil {
			if isNonRetriableSessionError(err) {
				return err
			}
			delay := retry.nextDelay(time.Now())
			if c.display != nil {
				c.display.ShowWarning(fmt.Sprintf("tunnel connect failed, %s; retrying in %s", shortenError(err), delay.Round(time.Second)))
			} else {
				c.log.Warn("tunnel connect failed", "err", err, "retry_in", delay.Round(time.Second).String())
			}
			select {
			case <-ctx.Done():
				return nil
			case <-autoUpdateCh:
				return ErrAutoUpdated
			case <-time.After(delay):
			}
			continue
		}
		retry.reset()

		if c.display != nil {
			c.display.ShowBanner(c.version)
			localAddr := fmt.Sprintf("http://localhost:%d", c.cfg.LocalPort)
			c.display.ShowTunnelInfo(reg.PublicURL, localAddr, reg.ServerTLSMode, reg.TunnelID, c.cfg.Protect, rt.transportKind())
			c.display.ShowVersions(c.version, versionutil.EnsureVPrefix(reg.ServerVersion), reg.WAFEnabled)
		} else {
			c.log.Info("tunnel ready", "public_url", reg.PublicURL, "tunnel_id", reg.TunnelID, "transport", rt.transportKind())
			if reg.ServerTLSMode != "" {
				c.log.Info("server tls mode", "mode", reg.ServerTLSMode)
			}
			if reg.ServerVersion != "" {
				c.log.Info("versions", "client", c.version, "server", versionutil.EnsureVPrefix(reg.ServerVersion), "waf_enabled", reg.WAFEnabled)
			}
		}
		if hook := c.hooks.OnTunnelReady; hook != nil {
			hook(TunnelReadyEvent{
				TunnelID:      reg.TunnelID,
				PublicURL:     reg.PublicURL,
				Transport:     rt.transportKind(),
				ServerVersion: reg.ServerVersion,
				ServerTLSMode: reg.ServerTLSMode,
				WAFEnabled:    reg.WAFEnabled,
			})
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

		err = rt.run()
		rt.close()
		if ctx.Err() != nil {
			return nil
		}
		if hook := c.hooks.OnSessionDrop; hook != nil {
			hook(SessionDisconnectEvent{Err: err})
		}
		if c.display != nil {
			reason := "unknown"
			if err != nil {
				reason = err.Error()
			}
			c.display.ShowReconnecting(reason)
		} else {
			delay := retry.nextDelay(time.Now())
			c.log.Warn("client disconnected; reconnecting", "err", err, "retry_in", delay.Round(time.Second).String())
		}
		delay := retry.nextDelay(time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-autoUpdateCh:
			return ErrAutoUpdated
		case <-time.After(delay):
		}
	}
}

func (r *reconnectSchedule) nextDelay(now time.Time) time.Duration {
	if r.startedAt.IsZero() {
		r.startedAt = now
		return reconnectInitialDelay
	}
	elapsed := now.Sub(r.startedAt)
	switch {
	case elapsed < reconnectInitialWindow:
		return reconnectInitialDelay
	case elapsed < reconnectInitialWindow+reconnectSecondStageWindow:
		return reconnectSecondStageDelay
	default:
		return reconnectThirdStageDelay
	}
}

func (r *reconnectSchedule) reset() {
	r.startedAt = time.Time{}
}

func (c *Client) runSession(ctx context.Context, localBase *url.URL, reg registerResponse) error {
	rt, err := newSessionRuntime(c, ctx, localBase, reg)
	if err != nil {
		return err
	}
	defer rt.close()
	return rt.run()
}
