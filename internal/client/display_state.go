package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/traffic"
)

// ShowBanner sets the version string and draws the initial screen.
func (d *Display) ShowBanner(version string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ensureRefreshLoopLocked()
	d.version = version
	if d.color {
		_, _ = fmt.Fprint(d.out, ansiHideCur)
	}
	d.redraw()
}

// Cleanup restores the terminal cursor. Call on shutdown.
func (d *Display) Cleanup() {
	d.mu.Lock()
	if d.wsDebounceTimer != nil {
		d.wsDebounceTimer.Stop()
		d.wsDebounceTimer = nil
	}
	if d.refreshStop != nil {
		close(d.refreshStop)
		d.refreshStop = nil
	}
	done := d.refreshDone
	d.refreshDone = nil
	if d.color {
		_, _ = fmt.Fprint(d.out, ansiShowCur)
	}
	d.mu.Unlock()
	if done != nil {
		<-done
	}
}

// ShowTunnelInfo updates the tunnel connection details and redraws.
func (d *Display) ShowTunnelInfo(publicURL, localAddr, tlsMode, tunnelID string, protected bool, transport string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ensureRefreshLoopLocked()
	now := d.now()
	if d.sessionStart.IsZero() {
		d.sessionStart = now
	}
	if d.onlineSince.IsZero() || !d.shouldPreserveOnlineSinceLocked(now) {
		d.onlineSince = now
	}
	if !d.sessionStart.IsZero() && d.status != "" {
		d.lastReconnect = now
	}
	d.setStatusLocked("online", now)
	d.publicURL = publicURL
	d.protected = protected
	d.localAddr = localAddr
	d.tlsMode = tlsMode
	d.transport = transport
	d.tunnelID = tunnelID
	if !d.sessionDetailsPinned {
		d.showSessionDetails = false
	}
	d.noticeText = ""
	d.noticeLevel = ""
	d.redraw()
}

// ShowVersions sets the client and server version strings and redraws.
func (d *Display) ShowVersions(clientVersion, serverVersion string, wafEnabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.version = clientVersion
	d.serverVersion = serverVersion
	d.wafEnabled = wafEnabled
	d.redraw()
}

// ShowUpdateStatus sets the available update version and redraws.
// Pass an empty string to indicate the client is up to date.
func (d *Display) ShowUpdateStatus(latestVersion string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.updateVersion = latestVersion
	d.redraw()
}

// ToggleSessionDetails shows or hides the extra session detail row.
func (d *Display) ToggleSessionDetails() {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.showSessionDetails && !d.sessionDetailsPinned:
		d.sessionDetailsPinned = true
	case d.showSessionDetails && d.sessionDetailsPinned:
		d.showSessionDetails = false
		d.sessionDetailsPinned = false
	default:
		d.showSessionDetails = true
		d.sessionDetailsPinned = true
	}
	d.redraw()
}

// ShowLatency updates the displayed round-trip latency and redraws.
func (d *Display) ShowLatency(rtt time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.latency = rtt
	d.redraw()
}

// ShowWAFStats updates the displayed WAF-blocked request count and redraws.
func (d *Display) ShowWAFStats(blocked int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wafBlocked = blocked
	d.redraw()
}

// ShowReconnecting sets the status to reconnecting and redraws.
func (d *Display) ShowReconnecting(reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ensureRefreshLoopLocked()
	if !d.showSessionDetails && !d.sessionStart.IsZero() {
		d.showSessionDetails = true
	}
	d.setStatusLocked("reconnecting", d.now())
	d.redraw()
}

func (d *Display) shouldPreserveOnlineSinceLocked(now time.Time) bool {
	if d.status != "reconnecting" || d.statusChangedAt.IsZero() || d.onlineSince.IsZero() {
		return false
	}
	return now.Sub(d.statusChangedAt) < displayMicroDisconnectMax
}

func (d *Display) ensureRefreshLoopLocked() {
	if d.refreshInterval <= 0 || d.refreshStop != nil {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	interval := d.refreshInterval
	d.refreshStop = stop
	d.refreshDone = done
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				d.mu.Lock()
				if d.status != "" {
					d.redraw()
				}
				d.mu.Unlock()
			}
		}
	}()
}

func (d *Display) setStatusLocked(status string, now time.Time) {
	status = strings.TrimSpace(status)
	prevStatus := d.status
	if prevStatus == "reconnecting" && status != "reconnecting" {
		d.finalizePendingDisconnectLocked(now)
	}
	if prevStatus != "reconnecting" && status == "reconnecting" && !d.sessionStart.IsZero() {
		d.pendingDisconnectAt = now
	}
	if status == "" {
		d.status = ""
		d.statusChangedAt = time.Time{}
		d.pendingDisconnectAt = time.Time{}
		return
	}
	if d.status != status || d.statusChangedAt.IsZero() {
		d.statusChangedAt = now
	}
	d.status = status
}

func (d *Display) finalizePendingDisconnectLocked(now time.Time) {
	if d.pendingDisconnectAt.IsZero() {
		return
	}
	downtime := now.Sub(d.pendingDisconnectAt)
	if downtime >= displayMicroDisconnectMax {
		d.sessionDowntime += downtime
		d.sessionDisconnects++
	}
	d.pendingDisconnectAt = time.Time{}
}

// LogRequest records an HTTP request and redraws.
// headers is used to extract the client IP (X-Forwarded-For) for tracking
// unique visitors. Pass nil if headers are not available.
func (d *Display) LogRequest(method, path string, status int, duration time.Duration, headers map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalHTTP++
	d.trackVisitor(headers)
	d.appendLatencySampleLocked(duration)
	now := d.now()
	d.appendEntry(requestEntry{
		ts:       now,
		method:   method,
		path:     path,
		status:   status,
		duration: duration,
	})
	d.redraw()
}

// TrackWSOpen registers a new WebSocket stream and redraws.
// headers is used to extract the client IP for tracking unique visitors.
func (d *Display) TrackWSOpen(id, path string, headers map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	fp := visitorFingerprint(headers)
	d.touchVisitor(fp)
	d.wsConns[id] = wsEntry{id: id, path: path, ts: d.now(), fingerprint: fp}
	d.redraw()
}

// TrackWSClose removes a WebSocket stream and redraws.
// A debounced display floor prevents the counter from briefly dipping
// during a page refresh (close + immediate reopen).
func (d *Display) TrackWSClose(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Capture the count *before* deletion as the display floor.
	preCloseCount := len(d.wsConns)
	delete(d.wsConns, id)

	// Set floor to the maximum of the existing floor and the pre-close count.
	// This handles rapid successive closes correctly.
	if preCloseCount > d.wsDisplayMin {
		d.wsDisplayMin = preCloseCount
	}

	// Cancel any previously pending debounce timer.
	if d.wsDebounceTimer != nil {
		d.wsDebounceTimer.Stop()
	}

	d.wsDebounceGen++
	gen := d.wsDebounceGen

	// After the debounce window, clear the floor and redraw with the real count.
	d.wsDebounceTimer = time.AfterFunc(wsCloseDebounce, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if gen != d.wsDebounceGen {
			return
		}
		d.wsDisplayMin = 0
		d.wsDebounceTimer = nil
		d.redraw()
	})

	d.redraw()
}

// ShowWarning sets the most recent warning notice and redraws.
func (d *Display) ShowWarning(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setNoticeLocked("warn", msg)
	d.redraw()
}

// ShowInfo sets the most recent info notice and redraws.
func (d *Display) ShowInfo(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.setNoticeLocked("info", msg)
	d.redraw()
}

func (d *Display) setNoticeLocked(level, msg string) {
	msg = strings.TrimSpace(msg)
	level = strings.ToLower(strings.TrimSpace(level))
	d.noticeText = msg
	d.noticeLevel = level
}

func (d *Display) RecordTraffic(direction traffic.Direction, bytes int64) {
	if d == nil || bytes <= 0 {
		return
	}
	now := d.now()
	if d.traffic == nil {
		d.traffic = traffic.NewMeter(traffic.DefaultWindow)
	}
	d.traffic.AddAt(now, direction, bytes)
}

// appendEntry adds a request entry to the rolling log, evicting the oldest
// entry when the log exceeds maxDisplayRequests. It copies into a new backing
// array to avoid retaining references from a growing underlying slice.
// Caller must hold d.mu.
func (d *Display) appendEntry(e requestEntry) {
	d.requests = append(d.requests, e)
	if len(d.requests) > maxDisplayRequests {
		copy(d.requests, d.requests[len(d.requests)-maxDisplayRequests:])
		d.requests = d.requests[:maxDisplayRequests]
	}
}

func (d *Display) appendLatencySampleLocked(v time.Duration) {
	if v < 0 {
		v = 0
	}
	d.latencySamples = append(d.latencySamples, v)
	if len(d.latencySamples) > displayLatencySampleMax {
		copy(d.latencySamples, d.latencySamples[len(d.latencySamples)-displayLatencySampleMax:])
		d.latencySamples = d.latencySamples[:displayLatencySampleMax]
	}
}

// trackVisitor builds a fingerprint from the request headers and updates
// the visitor's last-seen timestamp. Caller must hold d.mu.
func (d *Display) trackVisitor(headers map[string][]string) {
	fp := visitorFingerprint(headers)
	d.touchVisitor(fp)
}

// touchVisitor updates (or creates) the last-seen timestamp for a visitor
// fingerprint. Caller must hold d.mu.
func (d *Display) touchVisitor(fp string) {
	if fp != "" {
		d.visitors[fp] = d.now()
	}
}

// now returns the current time via the configurable clock.
func (d *Display) now() time.Time {
	if d.nowFunc != nil {
		return d.nowFunc()
	}
	return time.Now()
}

// activeClientCount returns the number of unique visitors considered active.
// A visitor is active if they were last seen within activeClientWindow OR
// they currently have an open WebSocket connection. Caller must hold d.mu.
func (d *Display) activeClientCount() int {
	now := d.now()
	cutoff := now.Add(-activeClientWindow)
	active := make(map[string]struct{}, len(d.visitors)+len(d.wsConns))

	// Count visitors seen within the window.
	for fp, lastSeen := range d.visitors {
		if lastSeen.After(cutoff) {
			active[fp] = struct{}{}
		}
	}

	// Open WebSocket connections always count as active.
	for _, ws := range d.wsConns {
		if ws.fingerprint != "" {
			active[ws.fingerprint] = struct{}{}
		}
	}

	return len(active)
}
