package client

import (
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI escape codes for terminal styling.
const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiRed       = "\033[31m"
	ansiGreen     = "\033[32m"
	ansiYellow    = "\033[33m"
	ansiCyan      = "\033[36m"
	ansiClearDown = "\033[J" // clear from cursor to end of screen
	ansiHome      = "\033[H" // move cursor to top-left
	ansiHideCur   = "\033[?25l"
	ansiShowCur   = "\033[?25h"
)

// displayFieldWidth is the column width for header field labels.
const displayFieldWidth = 26

// maxDisplayRequests is the number of HTTP request lines kept visible.
const maxDisplayRequests = 10

// activeClientWindow is the duration within which a visitor is considered
// "active" based on their last-seen timestamp. WebSocket connections also
// keep a visitor active for as long as the socket remains open.
const activeClientWindow = 60 * time.Second

// wsCloseDebounce is the delay before a WebSocket-close event triggers a
// screen redraw. During a page refresh the browser disconnects and
// reconnects quickly; the debounce prevents the counter from briefly
// dropping and causing visible flicker.
const wsCloseDebounce = 500 * time.Millisecond

// requestEntry stores one logged HTTP request for the rolling display.
type requestEntry struct {
	ts       time.Time
	method   string
	path     string
	status   int
	duration time.Duration
}

// wsEntry stores one active WebSocket connection for the display.
type wsEntry struct {
	id          string
	path        string
	ts          time.Time
	fingerprint string // visitor fingerprint (IP|UA)
}

// Display renders an ngrok-inspired terminal interface for the tunnel client.
// It redraws the entire screen on every state change so the header, counters,
// and request log are always visible. Safe for concurrent use.
type Display struct {
	out   io.Writer
	mu    sync.Mutex
	color bool

	// banner / header state
	version       string
	status        string // "online", "reconnecting", …
	tunnelID      string
	publicURL     string
	localAddr     string
	tlsMode       string
	serverVersion string
	updateVersion string // non-empty when an update is available

	// counters
	totalHTTP int // total HTTP requests forwarded

	// session timing
	sessionStart  time.Time // when the first successful connection happened
	lastReconnect time.Time // when the most recent reconnection happened (zero if none)

	// latency from most recent ping/pong round-trip
	latency time.Duration

	// unique visitor tracking (IP + User-Agent fingerprint → last seen)
	visitors map[string]time.Time

	// nowFunc returns the current time; override in tests.
	nowFunc func() time.Time

	// rolling request log (most recent at the end)
	requests []requestEntry

	// active WebSocket streams
	wsConns map[string]wsEntry

	// wsDisplayMin is the debounced floor for the displayed WebSocket
	// count. During a page refresh the browser disconnects and quickly
	// reconnects; by keeping the pre-close count as a floor, the
	// displayed value never dips below it until the debounce expires.
	wsDisplayMin    int
	wsDebounceTimer *time.Timer
	wsDebounceGen   uint64
}

// NewDisplay creates a Display that writes to stdout.
// When color is true, ANSI escape codes are used for styling.
func NewDisplay(color bool) *Display {
	return &Display{
		out:      os.Stdout,
		color:    color,
		wsConns:  make(map[string]wsEntry),
		visitors: make(map[string]time.Time),
		requests: make([]requestEntry, 0, maxDisplayRequests),
		nowFunc:  time.Now,
	}
}

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
func (d *Display) ShowVersions(clientVersion, serverVersion string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.version = clientVersion
	d.serverVersion = serverVersion
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

// visitorFingerprint returns a string that identifies a unique visitor
// using the combination of client IP (X-Forwarded-For / X-Real-Ip) and
// User-Agent. Returns empty string when no identifying info is available.
func visitorFingerprint(headers map[string][]string) string {
	if headers == nil {
		return ""
	}

	xff := firstHeaderValueCI(headers, "X-Forwarded-For")
	xri := firstHeaderValueCI(headers, "X-Real-Ip")
	ua := firstHeaderValueCI(headers, "User-Agent")

	var ip string
	if xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		ip = strings.TrimSpace(first)
	}
	if ip == "" {
		ip = strings.TrimSpace(xri)
	}
	if ip == "" {
		return ""
	}

	return ip + "|" + ua
}

// firstHeaderValueCI returns the first value for key from headers.
// It prefers exact/canonical map lookups, and falls back to case-insensitive
// matching for non-canonical maps.
func firstHeaderValueCI(headers map[string][]string, key string) string {
	if headers == nil || key == "" {
		return ""
	}
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	canonical := textproto.CanonicalMIMEHeaderKey(key)
	if canonical != key {
		if vals, ok := headers[canonical]; ok && len(vals) > 0 {
			return vals[0]
		}
	}
	for k, vals := range headers {
		if len(vals) == 0 {
			continue
		}
		if strings.EqualFold(k, key) {
			return vals[0]
		}
	}
	return ""
}

// redraw repaints the entire screen. Caller must hold d.mu.
func (d *Display) redraw() {
	var b strings.Builder

	// Move to top-left and clear.
	if d.color {
		b.WriteString(ansiHome)
		b.WriteString(ansiClearDown)
	}

	// ── Banner ──────────────────────────────────────────────────
	b.WriteString("\n")
	name := d.styled(ansiBold+ansiCyan, "expose")
	if d.version != "" {
		name += " " + d.styled(ansiDim, d.version)
	}
	hint := d.styled(ansiDim, "(Ctrl+C to quit)")
	visName := len("expose")
	if d.version != "" {
		visName += 1 + len(d.version)
	}
	gap := 60 - visName
	if gap < 4 {
		gap = 4
	}
	fmt.Fprintf(&b, "%s%s%s\n\n", name, strings.Repeat(" ", gap), hint)

	// ── Connection info ─────────────────────────────────────────
	placeholder := d.styled(ansiDim, "--")

	if d.status != "" {
		statusColor := ansiGreen
		if d.status != "online" {
			statusColor = ansiYellow
		}
		d.writeField(&b, "Session Status", d.styled(statusColor, d.status))
	} else {
		d.writeField(&b, "Session Status", placeholder)
	}
	if !d.sessionStart.IsZero() {
		now := d.now()
		total := now.Sub(d.sessionStart)
		uptime := displayFormatUptime(total)
		if !d.lastReconnect.IsZero() {
			sinceLast := now.Sub(d.lastReconnect)
			uptime += d.styled(ansiDim, fmt.Sprintf(" (since reconnect: %s)", displayFormatUptime(sinceLast)))
		}
		d.writeField(&b, "Session Uptime", uptime)
	}
	if d.tunnelID != "" {
		d.writeField(&b, "Tunnel ID", d.styled(ansiDim, d.tunnelID))
	} else {
		d.writeField(&b, "Tunnel ID", placeholder)
	}
	sv := d.serverVersion
	if sv == "" {
		sv = "--"
	}
	d.writeField(&b, "Server Version", d.styled(ansiDim, sv))
	if d.updateVersion != "" {
		d.writeField(&b, "Update",
			d.styled(ansiYellow, fmt.Sprintf("%s available", d.updateVersion))+
				d.styled(ansiDim, " — run ")+
				d.styled(ansiBold, "expose update"))
	}
	if d.latency > 0 {
		d.writeField(&b, "Latency", displayFormatDuration(d.latency))
	} else {
		d.writeField(&b, "Latency", placeholder)
	}
	if d.publicURL != "" {
		arrow := d.styled(ansiDim, "→")
		d.writeField(&b, "Forwarding", fmt.Sprintf("%s %s %s",
			d.styled(ansiCyan, d.publicURL), arrow, d.localAddr))
	} else {
		d.writeField(&b, "Forwarding", placeholder)
	}
	if d.tlsMode != "" {
		d.writeField(&b, "TLS Mode", d.tlsMode)
	} else {
		d.writeField(&b, "TLS Mode", placeholder)
	}

	// ── Connections counter ─────────────────────────────────────
	wsCount := len(d.wsConns)
	// Use the debounced floor so the counter never dips below the
	// pre-close value during a rapid refresh cycle.
	if d.wsDisplayMin > wsCount {
		wsCount = d.wsDisplayMin
	}
	activeCount := d.activeClientCount()
	clientCount := len(d.visitors)
	d.writeField(&b, "Clients", fmt.Sprintf("%d active, %d total", activeCount, clientCount))
	httpSummary := fmt.Sprintf("%d total", d.totalHTTP)
	if wsCount > 0 {
		d.writeField(&b, "WebSockets", fmt.Sprintf("%d open", wsCount))
	} else {
		d.writeField(&b, "WebSockets", placeholder)
	}

	b.WriteString("\n")

	// ── HTTP Requests (counters) ────────────────────────────────
	b.WriteString(d.styled(ansiBold, "HTTP Requests"))
	b.WriteString("  ")
	b.WriteString(d.styled(ansiDim, httpSummary))
	b.WriteString("\n")
	b.WriteString(d.styled(ansiDim, strings.Repeat("─", 78)))
	b.WriteString("\n")

	if len(d.requests) == 0 {
		b.WriteString(d.styled(ansiDim, "  Waiting for requests…"))
		b.WriteString("\n")
	} else {
		for _, r := range d.requests {
			ts := r.ts.Format("15:04:05")
			switch r.method {
			case "WARN":
				fmt.Fprintf(&b, "%s  %s  %s\n",
					d.styled(ansiDim, ts),
					d.styled(ansiYellow, "WARN   "),
					r.path,
				)
			case "INFO":
				fmt.Fprintf(&b, "%s  %s  %s\n",
					d.styled(ansiDim, ts),
					d.styled(ansiCyan, "INFO   "),
					r.path,
				)
			default:
				statusStr := d.formatStatus(r.status)
				dur := displayFormatDuration(r.duration)
				fmt.Fprintf(&b, "%s  %s  %-40s %s %s\n",
					d.styled(ansiDim, ts),
					d.styled(ansiBold, fmt.Sprintf("%-7s", r.method)),
					displayTruncatePath(r.path, 40),
					statusStr,
					d.styled(ansiDim, fmt.Sprintf("%7s", dur)),
				)
			}
		}
	}

	_, _ = fmt.Fprint(d.out, b.String())
}

// writeField writes a label–value pair aligned to displayFieldWidth.
func (d *Display) writeField(b *strings.Builder, label, value string) {
	pad := displayFieldWidth - len(label)
	if pad < 1 {
		pad = 1
	}
	fmt.Fprintf(b, "%s%s%s\n", label, strings.Repeat(" ", pad), value)
}

// formatStatus returns a colored status code and text string.
func (d *Display) formatStatus(code int) string {
	text := http.StatusText(code)
	if text == "" {
		text = "Unknown"
	}
	s := fmt.Sprintf("%-19s", fmt.Sprintf("%d %s", code, text))
	switch {
	case code >= 200 && code < 300:
		return d.styled(ansiGreen, s)
	case code >= 300 && code < 400:
		return d.styled(ansiCyan, s)
	case code >= 400 && code < 500:
		return d.styled(ansiYellow, s)
	default:
		return d.styled(ansiRed, s)
	}
}

// styled wraps text with ANSI codes when color is enabled.
func (d *Display) styled(code, text string) string {
	if !d.color {
		return text
	}
	return code + text + ansiReset
}

// displayTruncatePath shortens a path to fit within max visible characters.
func displayTruncatePath(path string, max int) string {
	if len(path) <= max {
		return path
	}
	if max <= 3 {
		return path[:max]
	}
	return path[:max-3] + "..."
}

// displayFormatDuration formats a duration for display in the request log.
func displayFormatDuration(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%dμs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

// displayFormatUptime formats a duration as a human-readable uptime string.
// The minimum displayed value is "1 minute". Components are days, hours, and
// minutes (e.g. "2 hours, 15 minutes" or "1 day, 3 hours").
func displayFormatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	var parts []string
	if days > 0 {
		if days == 1 {
			parts = append(parts, "1 day")
		} else {
			parts = append(parts, fmt.Sprintf("%d days", days))
		}
	}
	if hours > 0 {
		if hours == 1 {
			parts = append(parts, "1 hour")
		} else {
			parts = append(parts, fmt.Sprintf("%d hours", hours))
		}
	}
	if minutes > 0 || len(parts) == 0 {
		if minutes == 1 {
			parts = append(parts, "1 minute")
		} else {
			parts = append(parts, fmt.Sprintf("%d minutes", minutes))
		}
	}
	return strings.Join(parts, ", ")
}
