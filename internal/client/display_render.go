package client

import (
	"fmt"
	"net/http"
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
	if d.wafEnabled {
		sv += " (+WAF)"
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
