package client

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

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
	visHint := len("(Ctrl+C to quit)")
	visName := len("expose")
	if d.version != "" {
		visName += 1 + len(d.version)
	}
	gap := max(displayContentWidth-visName-visHint, 4)
	fmt.Fprintf(&b, "%s%s%s\n\n", name, strings.Repeat(" ", gap), hint)

	// ── Connection info ─────────────────────────────────────────
	placeholder := d.styled(ansiDim, "--")

	if d.status != "" {
		statusColor := ansiGreen
		if d.status != "online" {
			statusColor = ansiYellow
		}
		statusText := d.styled(statusColor, d.status)
		statusSince := d.statusChangedAt
		if statusSince.IsZero() {
			statusSince = d.sessionStart
		}
		if !statusSince.IsZero() {
			now := d.now()
			statusText += d.styled(ansiDim, " for ")
			statusText += displayFormatUptime(now.Sub(statusSince))
		}
		if d.tunnelID != "" {
			statusText += d.styled(ansiDim, " (ID: "+d.tunnelID+")")
		}
		d.writeField(&b, "Session", statusText)
	} else {
		statusText := placeholder
		if d.tunnelID != "" {
			statusText += d.styled(ansiDim, " (ID: "+d.tunnelID+")")
		}
		d.writeField(&b, "Session", statusText)
	}
	sv := d.serverVersion
	if sv == "" {
		sv = "--"
	}
	serverVersionValue := d.styled(ansiDim, sv)
	if sv != "--" {
		serverVersionValue = sv // default terminal color (white in dark themes)
	}
	meta := make([]string, 0, 2)
	if d.wafEnabled {
		meta = append(meta, "WAF: On")
	}
	if d.tlsMode != "" {
		meta = append(meta, "TLS: "+displayCapitalizeCSV(d.tlsMode))
	}
	if len(meta) > 0 {
		serverVersionValue += d.styled(ansiDim, " ("+strings.Join(meta, ", ")+")")
	}
	d.writeField(&b, "Server", serverVersionValue)
	if d.updateVersion != "" {
		d.writeField(&b, "Update",
			d.styled(ansiYellow, fmt.Sprintf("%s available", d.updateVersion))+
				d.styled(ansiDim, " - run ")+
				d.styled(ansiBold, "expose update")+
				d.styled(ansiDim, " or press ")+
				d.styled(ansiBold, "Ctrl+U"))
	}
	if d.latency > 0 {
		d.writeField(&b, "Latency", displayFormatDuration(d.latency))
	} else {
		d.writeField(&b, "Latency", placeholder)
	}
	if d.publicURL != "" {
		arrow := d.styled(ansiDim, "→")
		d.writeField(&b, "Forwarding", fmt.Sprintf("%s %s %s",
			d.styled(ansiCyan, d.publicURL), arrow, d.localTargetWithHealth(d.localAddr)))
	} else {
		d.writeField(&b, "Forwarding", placeholder)
	}
	// ── Connections counter ─────────────────────────────────────
	wsCount := max(
		// Use the debounced floor so the counter never dips below the
		// pre-close value during a rapid refresh cycle.
		d.wsDisplayMin, len(d.wsConns))
	activeCount := d.activeClientCount()
	clientCount := len(d.visitors)
	d.writeField(&b, "Clients", fmt.Sprintf("%d active, %d total", activeCount, clientCount))
	httpSummary := fmt.Sprintf("%d total", d.totalHTTP)
	if d.wafEnabled {
		if d.wafBlocked > 0 {
			httpSummary += ", " + d.styled(ansiRed, fmt.Sprintf("blocked %d", d.wafBlocked))
		} else {
			httpSummary += ", blocked 0"
		}
	}
	if wsCount > 0 {
		d.writeField(&b, "WebSockets", fmt.Sprintf("%d open", wsCount))
	} else {
		d.writeField(&b, "WebSockets", placeholder)
	}

	b.WriteString("\n")

	// ── HTTP Requests (counters) ────────────────────────────────
	b.WriteString(d.styled(ansiBold, "HTTP Requests    "))
	b.WriteString("  ")
	b.WriteString(d.styled(ansiDim, httpSummary))
	b.WriteString("\n")
	b.WriteString(d.styled(ansiDim, strings.Repeat("─", displayContentWidth)))
	b.WriteString("\n")

	if len(d.requests) == 0 {
		b.WriteString(d.styled(ansiDim, "Waiting for requests…"))
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
	if p, ok := displayLatencyPercentiles(d.latencySamples); ok {
		b.WriteString("\n")
		b.WriteString("Latency")
		pad := max(displayFieldWidth-len("Latency"), 1)
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(d.styled(ansiDim, "P50 "))
		b.WriteString(p.p50)
		b.WriteString(d.styled(ansiDim, " | "))
		b.WriteString(d.styled(ansiDim, "P90 "))
		b.WriteString(p.p90)
		b.WriteString(d.styled(ansiDim, " | "))
		b.WriteString(d.styled(ansiDim, "P95 "))
		b.WriteString(p.p95)
		b.WriteString(d.styled(ansiDim, " | "))
		b.WriteString(d.styled(ansiDim, "P99 "))
		b.WriteString(p.p99)
		b.WriteString("\n")
	}

	_, _ = fmt.Fprint(d.out, b.String())
}

// writeField writes a label–value pair aligned to displayFieldWidth.
func (d *Display) writeField(b *strings.Builder, label, value string) {
	pad := max(displayFieldWidth-len(label), 1)
	fmt.Fprintf(b, "%s%s%s\n", label, strings.Repeat(" ", pad), value)
}

// formatStatus returns a colored status code and text string.
func (d *Display) formatStatus(code int) string {
	text := http.StatusText(code)
	if text == "" {
		text = "Unknown"
	}
	s := fmt.Sprintf("%-10s", fmt.Sprintf("%d %s", code, text))
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

func (d *Display) localTargetWithHealth(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return d.styled(ansiDim, "--")
	}
	if d.localTargetHealthy(raw) {
		return raw + " " + d.styled(ansiGreen, "●")
	}
	return raw + " " + d.styled(ansiRed, "●")
}

func displayCapitalizeCSV(s string) string {
	parts := strings.Split(s, ",")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			parts[i] = part
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, ", ")
}

func (d *Display) localTargetHealthy(raw string) bool {
	cacheKey, dialAddr, ok := localTargetDialAddr(raw)
	if !ok {
		return false
	}
	if d.localHealth == nil {
		d.localHealth = make(map[string]localHealthEntry)
	}
	now := d.now()
	if e, ok := d.localHealth[cacheKey]; ok && now.Sub(e.checkedAt) < displayLocalHealthCacheTTL {
		return e.ok
	}
	conn, err := net.DialTimeout("tcp", dialAddr, displayLocalHealthTimeout)
	up := err == nil
	if err == nil {
		_ = conn.Close()
	}
	d.localHealth[cacheKey] = localHealthEntry{ok: up, checkedAt: now}
	return up
}

func localTargetDialAddr(raw string) (cacheKey string, dialAddr string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", "", false
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", "", false
		}
	}
	dialAddr = net.JoinHostPort(host, port)
	return dialAddr, dialAddr, true
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

type displayLatencyPercentilesValues struct {
	p50 string
	p90 string
	p95 string
	p99 string
}

func displayLatencyPercentiles(samples []time.Duration) (displayLatencyPercentilesValues, bool) {
	if len(samples) == 0 {
		return displayLatencyPercentilesValues{}, false
	}
	sorted := append([]time.Duration(nil), samples...)
	slices.Sort(sorted)
	return displayLatencyPercentilesValues{
		p50: displayFormatDuration(durationPercentile(sorted, 50)),
		p90: displayFormatDuration(durationPercentile(sorted, 90)),
		p95: displayFormatDuration(durationPercentile(sorted, 95)),
		p99: displayFormatDuration(durationPercentile(sorted, 99)),
	}, true
}

func durationPercentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	n := len(sorted)
	idx := (p*n + 99) / 100 // ceil(p*n/100)
	if idx <= 0 {
		idx = 1
	}
	if idx > n {
		idx = n
	}
	return sorted[idx-1]
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
