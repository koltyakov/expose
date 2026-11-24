package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/domain"
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
	ctx, cancel := context.WithCancel(ctx)
	var updateWG sync.WaitGroup
	defer func() {
		cancel()
		updateWG.Wait()
	}()

	// Auto-update: periodic background check + server-version-change trigger.
	autoUpdateCh := make(chan struct{}, 1)  // signals that the binary was replaced
	updateCheckCh := make(chan struct{}, 1) // asks the loop for an immediate check
	var lastServerVersion string
	var lastUpdateCheck time.Time
	if c.autoUpdate {
		updateWG.Add(1)
		go func() {
			defer updateWG.Done()
			c.runAutoUpdateLoop(ctx, updateCheckCh, autoUpdateCh)
		}()
	}

	var retry reconnectSchedule
	tlsProvisioningRetries := 0
	readyDeadline := time.Time{}
	if c.cfg.ReadyTimeout > 0 {
		readyDeadline = time.Now().Add(c.cfg.ReadyTimeout)
	}
	// readyWait caps the retry delay at the --ready-timeout deadline and
	// reports false once it passed without a tunnel ever having become ready.
	readyWait := func(delay time.Duration) (time.Duration, bool) {
		if readyDeadline.IsZero() {
			return delay, true
		}
		remaining := time.Until(readyDeadline)
		if remaining <= 0 {
			return 0, false
		}
		return min(delay, remaining), true
	}
	for {
		registerCtx, cancelRegister := ctx, context.CancelFunc(func() {})
		if !readyDeadline.IsZero() {
			// Bound a hung register (blackholed server) by the deadline too,
			// not only the waits between attempts.
			registerCtx, cancelRegister = context.WithDeadline(ctx, readyDeadline)
		}
		reg, err := c.register(registerCtx)
		registerTimedOut := errors.Is(registerCtx.Err(), context.DeadlineExceeded)
		cancelRegister()
		if err != nil && ctx.Err() == nil && registerTimedOut {
			return fmt.Errorf("tunnel not ready within %s: %w", c.cfg.ReadyTimeout, err)
		}
		if err != nil {
			delay, beforeDeadline := readyWait(retry.nextDelay(time.Now()))
			willRetry := !isNonRetriableRegisterError(err) && beforeDeadline
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
			if !beforeDeadline {
				return fmt.Errorf("tunnel not ready within %s: %w", c.cfg.ReadyTimeout, err)
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

		// A server version change usually means a new release is out. Ask the
		// background loop to check; the session is served meanwhile and ends
		// through autoUpdateCh if the binary gets replaced.
		if c.autoUpdate && lastServerVersion != "" && reg.ServerVersion != "" &&
			reg.ServerVersion != lastServerVersion {
			c.log.Info("server version changed", "from", lastServerVersion, "to", reg.ServerVersion)
			requestUpdateCheck(updateCheckCh)
		}
		if reg.ServerVersion != "" {
			lastServerVersion = reg.ServerVersion
		}

		rt, err := newSessionRuntime(c, ctx, localBase, reg)
		if err != nil {
			if isNonRetriableSessionError(err) {
				return err
			}
			delay, beforeDeadline := readyWait(retry.nextDelay(time.Now()))
			if !beforeDeadline {
				return fmt.Errorf("tunnel not ready within %s: %w", c.cfg.ReadyTimeout, err)
			}
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

		if c.display != nil {
			c.display.ShowBanner(c.version)
			localAddr := fmt.Sprintf("http://localhost:%d", c.cfg.LocalPort)
			if strings.TrimSpace(c.cfg.DisplayLocalAddr) != "" {
				c.display.SetLocalHealthTarget(localAddr)
				localAddr = strings.TrimSpace(c.cfg.DisplayLocalAddr)
			}
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
		readyDeadline = time.Time{} // later outages reconnect indefinitely
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

		// Check for updates in the background (non-blocking). Reconnects
		// re-register, so limit this to once per interval: a flapping link
		// otherwise spends GitHub's unauthenticated API quota.
		if !c.autoUpdate && (lastUpdateCheck.IsZero() || time.Since(lastUpdateCheck) >= updateNoticeInterval) {
			lastUpdateCheck = time.Now()
			updateWG.Add(1)
			go func() {
				defer updateWG.Done()
				c.checkForUpdates(ctx)
			}()
		}

		// Check if the background auto-update loop applied an update.
		select {
		case <-autoUpdateCh:
			rt.close()
			return ErrAutoUpdated
		default:
		}

		sessionStartedAt := time.Now()
		err = runSessionUntilInterrupt(ctx, rt, autoUpdateCh)
		if err == ErrAutoUpdated {
			return err
		}
		if shouldResetReconnectSchedule(sessionStartedAt, time.Now()) {
			retry.reset()
		}
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

func runSessionUntilInterrupt(ctx context.Context, rt sessionRuntime, autoUpdateCh <-chan struct{}) error {
	done := make(chan error, 1)
	go func() {
		done <- rt.run()
	}()

	select {
	case err := <-done:
		rt.close()
		return err
	case <-ctx.Done():
		rt.close()
		shutdownErr := <-done
		_ = shutdownErr // Report the interruption rather than the shutdown result.
		return ctx.Err()
	case <-autoUpdateCh:
		rt.close()
		shutdownErr := <-done
		_ = shutdownErr // Preserve the auto-update signal for the caller.
		return ErrAutoUpdated
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

func shouldResetReconnectSchedule(startedAt, now time.Time) bool {
	if startedAt.IsZero() {
		return false
	}
	return now.Sub(startedAt) >= reconnectInitialWindow
}

func (c *Client) runSession(ctx context.Context, localBase *url.URL, reg domain.RegisterResponse) error {
	rt, err := newSessionRuntime(c, ctx, localBase, reg)
	if err != nil {
		return err
	}
	defer rt.close()
	return rt.run()
}
