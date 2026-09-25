package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/termui"
)

type pubStatsHTTPError struct{ status int }

func (e pubStatsHTTPError) Error() string {
	switch e.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "stats access denied; use the API key that owns the publication"
	case http.StatusNotFound, http.StatusGone:
		return "published site not found, expired, or deleted"
	default:
		return fmt.Sprintf("stats request returned HTTP %d", e.status)
	}
}

func fetchPublishedStats(ctx context.Context, client *http.Client, endpoint, key string) (domain.PublishedSiteStats, error) {
	var stats domain.PublishedSiteStats
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return stats, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return stats, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return stats, pubStatsHTTPError{resp.StatusCode}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&stats); err != nil {
		return stats, err
	}
	if stats.Site.ID == "" || stats.Site.Hostname == "" {
		return stats, fmt.Errorf("server returned invalid site stats")
	}
	return stats, nil
}

// connectPublishedSite observes hosting through authenticated snapshots. It never
// changes the site's content, expiry, or hosting lifecycle.
func connectPublishedSite(ctx context.Context, client *http.Client, baseURL, key, target string, out io.Writer, interactive, jsonOutput bool, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	display := pubStatsDisplay{out: out, interactive: interactive && !jsonOutput}
	defer display.close()
	encoder := json.NewEncoder(out)
	delay := interval
	for {
		if ctx.Err() != nil {
			return nil
		}
		started := time.Now()
		stats, err := fetchPublishedStats(ctx, client, baseURL+"/"+url.PathEscape(target)+"/stats", key)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			var status pubStatsHTTPError
			if errors.As(err, &status) && status.status < 500 && status.status != http.StatusTooManyRequests {
				return err
			}
			// Keep credentials and request URLs out of retry messages.
			if !jsonOutput {
				if err := display.retry(); err != nil {
					return err
				}
			}
			delay = min(max(delay*2, time.Second), 10*time.Second)
		} else {
			// Pin the publication identity so a later hostname reuse cannot silently
			// attach this dashboard to a different site.
			target = stats.Site.ID
			delay = interval
			if jsonOutput {
				err = encoder.Encode(stats)
			} else {
				err = display.render(stats, time.Since(started))
			}
			if err != nil {
				return err
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

type pubStatsDisplay struct {
	out         io.Writer
	interactive bool
	started     bool
	previous    *domain.PublishedSiteStats
}

func (d *pubStatsDisplay) close() {
	if d.interactive && d.started {
		_, _ = fmt.Fprint(d.out, termui.ShowCur, "\n")
	}
}

func (d *pubStatsDisplay) retry() error {
	prefix := ""
	if d.interactive {
		prefix = termui.Home + termui.ClearDown
	}
	_, err := fmt.Fprintln(d.out, prefix+"Stats connection interrupted. Reconnecting... The site stays hosted.")
	return err
}

func (d *pubStatsDisplay) render(stats domain.PublishedSiteStats, roundTrip time.Duration) error {
	var b strings.Builder
	if d.interactive {
		if !d.started {
			b.WriteString(termui.HideCur)
			d.started = true
		}
		b.WriteString(termui.Home + termui.ClearDown)
	}
	style := termui.Styler{Color: d.interactive}
	columns := termui.TerminalColumnsForWriter(d.out)
	if columns <= 0 {
		columns = 79
	}
	width := max(columns-1, 1)
	// Clip plain text before styling so narrow terminals never split ANSI codes.
	remaining := width
	part := func(code, text string) {
		text = config.SanitizeTerminalString(text)
		if d.interactive {
			text = termui.TruncateRight(text, remaining)
			remaining -= termui.VisibleRuneCount(text)
		}
		b.WriteString(style.Style(code, text))
	}
	newline := func() { b.WriteByte('\n'); remaining = width }
	field := func(label, value string) {
		part("", fmt.Sprintf("%-19s", label))
		part("", value)
		newline()
	}
	newline()
	part(termui.Bold+termui.Cyan, "expose")
	part(termui.Dim, " "+Version)
	hint := "(Ctrl+C to disconnect)"
	part("", strings.Repeat(" ", max(min(width, 78)-len("expose "+Version)-len(hint), 1)))
	part(termui.Dim, hint)
	newline()
	newline()
	part("", fmt.Sprintf("%-19s", "Session"))
	part(termui.Green, "connected")
	part(termui.Dim, " (published site)")
	newline()
	wafMode := "Off"
	if stats.WAFEnabled {
		wafMode = "On"
		if stats.WAFAuditOnly {
			wafMode = "Audit only"
		}
	}
	part("", fmt.Sprintf("%-19s", "Server"))
	part("", stats.ServerVersion)
	part(termui.Dim, " (WAF: "+wafMode+")")
	newline()
	field("Latency", termui.FormatDurationRounded(roundTrip))
	part("", fmt.Sprintf("%-19s", "Public URL"))
	part(termui.Cyan, "https://"+stats.Site.Hostname)
	newline()
	expiry := "no expiry"
	if stats.Site.ExpiresAt != nil {
		expiry = stats.Site.ExpiresAt.Format(time.RFC3339)
	}
	field("Expires", expiry)
	field("Stats since", stats.Since.Format(time.RFC3339))
	field("Updated", stats.CapturedAt.Format(time.RFC3339))
	visitorSuffix := ""
	if stats.VisitorsCapped {
		visitorSuffix = " (tracking limit reached)"
	}
	field("Visitors", fmt.Sprintf("%d tracked, %d active in last minute%s", stats.Visitors, stats.ActiveVisitors, visitorSuffix))
	var rate float64
	if previous := d.previous; previous != nil && previous.Since.Equal(stats.Since) && stats.ResponseBytes >= previous.ResponseBytes {
		if seconds := stats.CapturedAt.Sub(previous.CapturedAt).Seconds(); seconds > 0 {
			rate = float64(stats.ResponseBytes-previous.ResponseBytes) / seconds
		}
	}
	part("", fmt.Sprintf("%-19s%s sent ", "Traffic", pubFormatBytes(float64(stats.ResponseBytes))))
	part(termui.Dim, fmt.Sprintf("(%s/s)", pubFormatBytes(rate)))
	newline()
	newline()
	part(termui.Bold, fmt.Sprintf("%-19s", "HTTP Requests"))
	part(termui.Dim, fmt.Sprintf("%d total", stats.HTTPRequests))
	if stats.WAFEnabled || stats.WAFBlocked > 0 || stats.WAFAudited > 0 {
		part(termui.Dim, ", ")
		color := termui.Dim
		if stats.WAFBlocked > 0 {
			color = termui.Red
		}
		part(color, fmt.Sprintf("blocked %d", stats.WAFBlocked))
		part(termui.Dim, fmt.Sprintf(", audited %d", stats.WAFAudited))
	}
	newline()
	part(termui.Dim, strings.Repeat("─", min(width, 78)))
	newline()
	visible := 10
	if d.interactive {
		if f, ok := d.out.(*os.File); ok {
			if _, rows, err := term.GetSize(int(f.Fd())); err == nil {
				visible = min(visible, max(rows-20, 1))
			}
		}
	}
	requests := stats.Requests[max(len(stats.Requests)-visible, 0):]
	for _, request := range requests {
		status := fmt.Sprintf("%d %s", request.Status, http.StatusText(request.Status))
		color := termui.Red
		switch {
		case request.Status >= 200 && request.Status < 300:
			color = termui.Green
		case request.Status >= 300 && request.Status < 400:
			color = termui.Cyan
		case request.Status >= 400 && request.Status < 500:
			color = termui.Yellow
		}
		if request.AuditOnly {
			status = "audit"
			color = termui.Yellow
		}
		path := config.SanitizeTerminalString(request.Path)
		if request.WAFRule != "" {
			path += fmt.Sprintf(" [WAF: %s]", config.SanitizeTerminalString(request.WAFRule))
		}
		pathWidth := min(40, max(width-39, 8))
		part(termui.Dim, request.Time.Format("15:04:05")+"  ")
		part(termui.Bold, fmt.Sprintf("%-7s", config.SanitizeTerminalString(request.Method)))
		part("", fmt.Sprintf("  %-*s ", pathWidth, termui.TruncateRight(path, pathWidth)))
		part(color, fmt.Sprintf("%-10s", status))
		part(termui.Dim, fmt.Sprintf(" %7s", termui.FormatDurationRounded(time.Duration(request.DurationMS*float64(time.Millisecond)))))
		newline()
	}
	if len(stats.Requests) == 0 {
		part(termui.Dim, "Waiting for requests…")
		newline()
	}
	newline()
	part("", fmt.Sprintf("%-19s", "Request latency"))
	part(termui.Dim, "P50 ")
	part("", fmt.Sprintf("%.2f ms", stats.LatencyP50MS))
	part(termui.Dim, " | P95 ")
	part("", fmt.Sprintf("%.2f ms", stats.LatencyP95MS))
	newline()
	part(termui.Dim, "The site stays hosted after disconnecting.")
	newline()
	if !d.interactive {
		b.WriteByte('\n')
	}
	_, err := io.WriteString(d.out, b.String())
	d.previous = &stats
	return err
}

func pubFormatBytes(n float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	unit := 0
	for n >= 1024 && unit < len(units)-1 {
		n /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", n, units[unit])
}
