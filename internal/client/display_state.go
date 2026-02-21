package client

import (
	"fmt"
	"time"
)

// ShowBanner sets the version string and draws the initial screen.
func (d *Display) ShowBanner(version string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.version = version
	if d.color {
		_, _ = fmt.Fprint(d.out, ansiHideCur)
	}
	d.redraw()
}

// Cleanup restores the terminal cursor. Call on shutdown.
func (d *Display) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.wsDebounceTimer != nil {
		d.wsDebounceTimer.Stop()
		d.wsDebounceTimer = nil
	}
	if d.color {
		_, _ = fmt.Fprint(d.out, ansiShowCur)
	}
}

// ShowTunnelInfo updates the tunnel connection details and redraws.
func (d *Display) ShowTunnelInfo(publicURL, localAddr, tlsMode, tunnelID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if d.sessionStart.IsZero() {
		d.sessionStart = now
	} else {
		d.lastReconnect = now
	}
	d.status = "online"
	d.publicURL = publicURL
	d.localAddr = localAddr
	d.tlsMode = tlsMode
	d.tunnelID = tunnelID
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
	d.status = "reconnecting"
	d.redraw()
}

// LogRequest records an HTTP request and redraws.
// headers is used to extract the client IP (X-Forwarded-For) for tracking
// unique visitors. Pass nil if headers are not available.
func (d *Display) LogRequest(method, path string, status int, duration time.Duration, headers map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalHTTP++
	d.trackVisitor(headers)
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

// ShowWarning appends a warning pseudo-request line and redraws.
func (d *Display) ShowWarning(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.appendEntry(requestEntry{
		ts:     d.now(),
		method: "WARN",
		path:   msg,
	})
	d.redraw()
}

// ShowInfo appends an info pseudo-request line and redraws.
func (d *Display) ShowInfo(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.appendEntry(requestEntry{
		ts:     d.now(),
		method: "INFO",
		path:   msg,
	})
	d.redraw()
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
