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
	fmt.Fprintln(&b, style.Style(termui.Bold+termui.Cyan, "expose pub"), " live site stats")
	fmt.Fprintln(&b, "Ctrl+C disconnects. The site stays hosted.")
	fmt.Fprintln(&b)
	columns := termui.TerminalColumnsForWriter(d.out)
	if columns <= 0 {
		columns = 100
	}
	line := func(text string) {
		if d.interactive {
			text = termui.TruncateRight(text, max(columns-1, 1))
		}
		fmt.Fprintln(&b, text)
	}
	field := func(label, value string) { line(fmt.Sprintf("%-19s %s", label, config.SanitizeTerminalString(value))) }
	field("Status", "connected")
	field("Public URL", "https://"+stats.Site.Hostname)
	expiry := "no expiry"
	if stats.Site.ExpiresAt != nil {
		expiry = stats.Site.ExpiresAt.Format(time.RFC3339)
	}
	field("Expires", expiry)
	field("Server", stats.ServerVersion)
	field("Stats since", stats.Since.Format(time.RFC3339))
	field("Updated", stats.CapturedAt.Format(time.RFC3339))
	field("Connection RTT", termui.FormatDurationRounded(roundTrip))
	field("HTTP requests", fmt.Sprintf("%d", stats.HTTPRequests))
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
	field("Response traffic", fmt.Sprintf("%s sent, %s/s", pubFormatBytes(float64(stats.ResponseBytes)), pubFormatBytes(rate)))
	field("Request latency", fmt.Sprintf("p50 %.2f ms, p95 %.2f ms", stats.LatencyP50MS, stats.LatencyP95MS))
	wafMode := "disabled"
	if stats.WAFEnabled {
		wafMode = "enabled"
	}
	if stats.WAFAuditOnly && stats.WAFEnabled {
		wafMode = "audit only"
	}
	field("WAF", fmt.Sprintf("%s, %d blocked, %d audited", wafMode, stats.WAFBlocked, stats.WAFAudited))
	fmt.Fprintln(&b, "\nRecent requests")
	visible := 10
	if d.interactive {
		if f, ok := d.out.(*os.File); ok {
			if _, rows, err := term.GetSize(int(f.Fd())); err == nil {
				visible = min(visible, max(rows-19, 1))
			}
		}
	}
	requests := stats.Requests[max(len(stats.Requests)-visible, 0):]
	for _, request := range requests {
		status := fmt.Sprintf("%d", request.Status)
		if request.AuditOnly {
			status = "audit"
		}
		text := fmt.Sprintf("%s  %-7s %5s %8.2f ms  %s", request.Time.Format("15:04:05"), config.SanitizeTerminalString(request.Method), status, request.DurationMS, config.SanitizeTerminalString(request.Path))
		if request.WAFRule != "" {
			text += fmt.Sprintf(" [WAF: %s]", config.SanitizeTerminalString(request.WAFRule))
		}
		line(text)
	}
	if len(stats.Requests) == 0 {
		fmt.Fprintln(&b, "Waiting for requests...")
	}
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
