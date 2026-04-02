package client

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/termui"
	"github.com/koltyakov/expose/internal/traffic"
)

// redraw repaints the entire screen. Caller must hold d.mu.
func (d *Display) redraw() {
	var b strings.Builder
	renderNow := d.now()

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
	trafficSnapshot := trafficSnapshotForDisplayAt(d, renderNow)

	if d.status != "" {
		statusColor := ansiGreen
		if d.status != "online" {
			statusColor = ansiYellow
		}
		statusText := d.styled(statusColor, d.status)
		statusSince := d.statusChangedAt
		if d.status == "online" && !d.onlineSince.IsZero() {
			statusSince = d.onlineSince
		}
		if statusSince.IsZero() {
			statusSince = d.sessionStart
		}
		if !statusSince.IsZero() {
			statusText += d.styled(ansiDim, " for ")
			statusText += displayFormatUptime(renderNow.Sub(statusSince))
		}
		if detail := d.sessionDetail(renderNow); detail != "" {
			statusText += d.styled(ansiDim, " ("+detail+")")
		}
		d.writeField(&b, "Session", statusText)
	} else {
		statusText := placeholder
		if detail := d.sessionDetail(renderNow); detail != "" {
			statusText += d.styled(ansiDim, " ("+detail+")")
		}
		d.writeField(&b, "Session", statusText)
	}
	if d.showSessionDetails {
		if details := d.sessionStatsDetail(renderNow); details != "" {
			d.writeField(&b, "", details)
		}
	}
	if d.noticeText != "" && d.status == "reconnecting" {
		d.writeField(&b, "", d.noticeDisplayText())
	}
	sv := d.serverVersion
	if sv == "" {
		sv = "--"
	}
	serverVersionValue := d.styled(ansiDim, sv)
	if sv != "--" {
		serverVersionValue = sv // default terminal color (white in dark themes)
	}
	meta := make([]string, 0, 3)
	if d.wafEnabled {
		meta = append(meta, "WAF: On")
	}
	if d.tlsMode != "" {
		meta = append(meta, "TLS: "+displayCapitalizeCSV(d.tlsMode))
	}
	if d.transport != "" {
		meta = append(meta, "Transport: "+strings.ToUpper(d.transport))
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
		d.writeFieldLines(&b, "Forwarding", d.forwardingDisplayLines())
	} else {
		d.writeField(&b, "Forwarding", placeholder)
	}
	if d.noticeText != "" && d.status != "reconnecting" {
		d.writeField(&b, "", d.noticeDisplayText())
	}
	// ── Connections counter ─────────────────────────────────────
	wsCount := max(
		// Use the debounced floor so the counter never dips below the
		// pre-close value during a rapid refresh cycle.
		d.wsDisplayMin, len(d.wsConns))
	activeCount := d.activeClientCount()
	clientCount := len(d.visitors)
	d.writeField(&b, "Traffic", d.trafficCombinedSummaryText(trafficSnapshot))
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
	d.writeFieldLines(b, label, []string{value})
}

func (d *Display) writeFieldLines(b *strings.Builder, label string, values []string) {
	termui.WriteFieldLines(b, displayFieldWidth, label, values)
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
	return termui.Styler{Color: d.color}.Style(code, text)
}

func displayCapitalizeCSV(s string) string {
	return termui.CapitalizeCSV(s)
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
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	if !strings.Contains(raw, "://") {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return "", "", false
		}
		dialAddr = net.JoinHostPort(strings.TrimSpace(host), strings.TrimSpace(port))
		return dialAddr, dialAddr, true
	}
	u, err := url.Parse(raw)
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
	return termui.FormatDurationRounded(d)
}

func trafficSnapshotForDisplayAt(d *Display, now time.Time) traffic.Snapshot {
	if d == nil || d.traffic == nil {
		return traffic.Snapshot{}
	}
	return d.traffic.SnapshotAt(now)
}

func (d *Display) trafficSummaryText(total, rate int64) string {
	return traffic.FormatBytes(total) + " total " + d.styled(ansiDim, "("+traffic.FormatRate(rate)+")")
}

func (d *Display) trafficCombinedSummaryText(snapshot traffic.Snapshot) string {
	return d.trafficStyledSegment("In", d.trafficSummaryText(snapshot.InboundTotal, snapshot.InboundRate)) +
		" " + d.styled(ansiDim, "|") + " " +
		d.trafficStyledSegment("Out", d.trafficSummaryText(snapshot.OutboundTotal, snapshot.OutboundRate))
}

func (d *Display) trafficStyledSegment(label, value string) string {
	return label + " " + value
}

func displayFormatStartedAt(t time.Time) string {
	return t.Format("2006-01-02 15:04:05 MST")
}

func (d *Display) sessionDetail(now time.Time) string {
	switch {
	case d.tunnelID == "" && d.sessionStart.IsZero():
		return ""
	case d.tunnelID == "":
		return "Started: " + displayFormatStartedAt(d.sessionStart)
	case d.sessionStart.IsZero():
		return "ID: " + d.tunnelID
	}

	idFor := displaySessionDetailIDFor
	startFor := displaySessionDetailStartFor
	if idFor <= 0 {
		idFor = 15 * time.Second
	}
	if startFor <= 0 {
		startFor = 30 * time.Second
	}
	cycle := idFor + startFor
	if cycle <= 0 {
		return "ID: " + d.tunnelID
	}
	elapsed := max(now.Sub(d.sessionStart), 0)
	if elapsed%cycle < idFor {
		return "ID: " + d.tunnelID
	}
	return "Started: " + displayFormatStartedAt(d.sessionStart)
}

func (d *Display) sessionStatsDetail(now time.Time) string {
	if d.sessionStart.IsZero() {
		return ""
	}
	parts := make([]string, 0, 3)
	if downtime := d.sessionDisplayedDowntime(now); downtime > 0 {
		parts = append(parts, "downtime "+displayFormatDowntime(downtime))
	}
	parts = append(parts, fmt.Sprintf("%.1f%% uptime", d.sessionUptimePercent(now)))
	if disconnects := d.sessionDisconnectCount(now); disconnects > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", disconnects, pluralizeCount(disconnects, "disconnect", "disconnects")))
	}
	return strings.Join(parts, ", ")
}

func (d *Display) sessionUptimePercent(now time.Time) float64 {
	if d.sessionStart.IsZero() {
		return 0
	}
	elapsed := now.Sub(d.sessionStart)
	if elapsed <= 0 {
		return 100
	}
	downtime := min(max(d.sessionEffectiveDowntime(now), 0), elapsed)
	uptime := elapsed - downtime
	pct := float64(uptime) / float64(elapsed) * 100
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func (d *Display) sessionDisconnectCount(now time.Time) int {
	count := d.sessionDisconnects
	if d.status == "reconnecting" && !d.pendingDisconnectAt.IsZero() && now.Sub(d.pendingDisconnectAt) >= displayMicroDisconnectMax {
		count++
	}
	return count
}

func (d *Display) sessionEffectiveDowntime(now time.Time) time.Duration {
	downtime := d.sessionDowntime
	if d.status == "reconnecting" && !d.pendingDisconnectAt.IsZero() && now.Sub(d.pendingDisconnectAt) >= displayMicroDisconnectMax {
		downtime += now.Sub(d.pendingDisconnectAt)
	}
	return downtime
}

func (d *Display) sessionCurrentDowntime(now time.Time) time.Duration {
	if d.status != "reconnecting" || d.pendingDisconnectAt.IsZero() {
		return 0
	}
	downtime := now.Sub(d.pendingDisconnectAt)
	if downtime < 0 {
		return 0
	}
	return downtime
}

func (d *Display) sessionDisplayedDowntime(now time.Time) time.Duration {
	return d.sessionDowntime + d.sessionCurrentDowntime(now)
}

func (d *Display) noticeDisplayText() string {
	notice := d.noticeText
	switch d.noticeLevel {
	case "warn":
		return d.styled(ansiYellow, notice)
	case "info":
		return d.styled(ansiCyan, notice)
	default:
		return notice
	}
}

func pluralizeCount(v int, singular, plural string) string {
	if v == 1 {
		return singular
	}
	return plural
}

func displayFormatDowntime(d time.Duration) string {
	return termui.FormatDowntime(d)
}

type displayLatencyPercentilesValues struct {
	p50 string
	p90 string
	p95 string
	p99 string
}

func displayLatencyPercentiles(samples []time.Duration) (displayLatencyPercentilesValues, bool) {
	values, ok := termui.FormatLatencyPercentiles(samples, displayFormatDuration)
	if !ok {
		return displayLatencyPercentilesValues{}, false
	}
	return displayLatencyPercentilesValues{
		p50: values.P50,
		p90: values.P90,
		p95: values.P95,
		p99: values.P99,
	}, true
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
