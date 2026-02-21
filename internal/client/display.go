package client

import (
	"fmt"
	"io"
	"net/http"
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
	id   string
	path string
	ts   time.Time
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
	activeHTTP int // in-flight HTTP forwards
	totalHTTP  int // total HTTP requests forwarded

	// unique visitor tracking (IP + User-Agent fingerprint)
	visitors map[string]struct{}

	// rolling request log (most recent at the end)
	requests []requestEntry

	// active WebSocket streams
	wsConns map[string]wsEntry
}

// NewDisplay creates a Display that writes to stdout.
// When color is true, ANSI escape codes are used for styling.
func NewDisplay(color bool) *Display {
	return &Display{
		out:      os.Stdout,
		color:    color,
		wsConns:  make(map[string]wsEntry),
		visitors: make(map[string]struct{}),
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
	if d.color {
		_, _ = fmt.Fprint(d.out, ansiShowCur)
	}
}

// ShowTunnelInfo updates the tunnel connection details and redraws.
func (d *Display) ShowTunnelInfo(publicURL, localAddr, tlsMode, tunnelID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
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
	d.appendEntry(requestEntry{
		ts:       time.Now(),
		method:   method,
		path:     path,
		status:   status,
		duration: duration,
	})
	d.redraw()
}

// TrackHTTPStart increments the active HTTP counter and redraws.
func (d *Display) TrackHTTPStart() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.activeHTTP++
	d.redraw()
}

// TrackHTTPDone decrements the active HTTP counter and redraws.
func (d *Display) TrackHTTPDone() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activeHTTP > 0 {
		d.activeHTTP--
	}
	d.redraw()
}

// TrackWSOpen registers a new WebSocket stream and redraws.
// headers is used to extract the client IP for tracking unique visitors.
func (d *Display) TrackWSOpen(id, path string, headers map[string][]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.trackVisitor(headers)
	d.wsConns[id] = wsEntry{id: id, path: path, ts: time.Now()}
	d.redraw()
}

// TrackWSClose removes a WebSocket stream and redraws.
func (d *Display) TrackWSClose(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.wsConns, id)
	d.redraw()
}

// ShowWarning appends a warning pseudo-request line and redraws.
func (d *Display) ShowWarning(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.appendEntry(requestEntry{
		ts:     time.Now(),
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
		ts:     time.Now(),
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

// trackVisitor builds a fingerprint from the request headers and adds it
// to the unique visitors set. Caller must hold d.mu.
func (d *Display) trackVisitor(headers map[string][]string) {
	fp := visitorFingerprint(headers)
	if fp != "" {
		d.visitors[fp] = struct{}{}
	}
}

// visitorFingerprint returns a string that identifies a unique visitor
// using the combination of client IP (X-Forwarded-For / X-Real-Ip) and
// User-Agent. Returns empty string when no identifying info is available.
func visitorFingerprint(headers map[string][]string) string {
	if headers == nil {
		return ""
	}

	var xff, xri, ua string
	for k, vals := range headers {
		if len(vals) == 0 {
			continue
		}
		switch strings.ToLower(k) {
		case "x-forwarded-for":
			if xff == "" {
				xff = vals[0]
			}
		case "x-real-ip":
			if xri == "" {
				xri = vals[0]
			}
		case "user-agent":
			if ua == "" {
				ua = vals[0]
			}
		}
	}

	var ip string
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	}
	if ip == "" {
		ip = strings.TrimSpace(xri)
	}
	if ip == "" {
		return ""
	}

	return ip + "|" + ua
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
	if d.status != "" {
		statusColor := ansiGreen
		if d.status != "online" {
			statusColor = ansiYellow
		}
		d.writeField(&b, "Session Status", d.styled(statusColor, d.status))
	}
	if d.tunnelID != "" {
		d.writeField(&b, "Tunnel ID", d.styled(ansiDim, d.tunnelID))
	}
	if d.version != "" || d.serverVersion != "" {
		cv := d.version
		if cv == "" {
			cv = "unknown"
		}
		sv := d.serverVersion
		if sv == "" {
			sv = "unknown"
		}
		d.writeField(&b, "Version", fmt.Sprintf("client: %s / server: %s", d.styled(ansiDim, cv), d.styled(ansiDim, sv)))
	}
	if d.updateVersion != "" {
		d.writeField(&b, "Update",
			d.styled(ansiYellow, fmt.Sprintf("v%s available", d.updateVersion))+
				d.styled(ansiDim, " — run ")+
				d.styled(ansiBold, "expose update"))
	}
	if d.publicURL != "" {
		arrow := d.styled(ansiDim, "→")
		d.writeField(&b, "Forwarding", fmt.Sprintf("%s %s %s",
			d.styled(ansiCyan, d.publicURL), arrow, d.localAddr))
	}
	if d.tlsMode != "" {
		d.writeField(&b, "TLS Mode", d.tlsMode)
	}

	// ── Connections counter ─────────────────────────────────────
	wsCount := len(d.wsConns)
	clientCount := len(d.visitors)
	visitorLabel := "visitors"
	if clientCount == 1 {
		visitorLabel = "visitor"
	}
	d.writeField(&b, "Clients", fmt.Sprintf("%d unique %s", clientCount, visitorLabel))
	httpParts := []string{
		fmt.Sprintf("%d in-flight", d.activeHTTP),
		fmt.Sprintf("%d total", d.totalHTTP),
	}
	d.writeField(&b, "HTTP Requests", strings.Join(httpParts, ", "))
	if wsCount > 0 {
		d.writeField(&b, "WebSockets", fmt.Sprintf("%d open", wsCount))
	}

	b.WriteString("\n")

	// ── HTTP Requests ───────────────────────────────────────────
	b.WriteString(d.styled(ansiBold, "HTTP Requests"))
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
