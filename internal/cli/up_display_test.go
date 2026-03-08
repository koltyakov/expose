package cli

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/traffic"
)

func newTestUpDashboard(now time.Time) (*upDashboard, *bytes.Buffer) {
	var out bytes.Buffer
	d := newUpDashboard("expose.yml", "dev")
	d.out = &out
	d.color = false
	d.nowFunc = func() time.Time { return now }
	d.InitGroups([]string{"app"}, map[string][]upLocalRoute{
		"app": {{
			Name:      "app",
			Subdomain: "app",
			LocalPort: 3000,
		}},
	}, false)
	return d, &out
}

func TestUpDashboardShowsAggregatedTraffic(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	d := newUpDashboard("expose.yml", "dev")
	d.out = &out
	d.color = false
	d.nowFunc = func() time.Time { return now }

	d.RecordTraffic("app", traffic.DirectionInbound, 1024)
	d.RecordTraffic("api", traffic.DirectionInbound, 512)
	d.RecordTraffic("app", traffic.DirectionOutbound, 2048)

	d.mu.Lock()
	d.redrawLocked()
	d.mu.Unlock()
	rendered := out.String()

	if !strings.Contains(rendered, "Traffic") || !strings.Contains(rendered, "In 1.5 KB total (1.5 KB/s) | Out 2 KB total (2 KB/s)") {
		t.Fatalf("expected aggregated traffic, got: %s", rendered)
	}

	now = now.Add(1100 * time.Millisecond)
	out.Reset()
	d.mu.Lock()
	d.redrawLocked()
	d.mu.Unlock()
	rendered = out.String()

	if !strings.Contains(rendered, "Traffic") || !strings.Contains(rendered, "In 1.5 KB total (0 B/s) | Out 2 KB total (0 B/s)") {
		t.Fatalf("expected traffic rate to decay, got: %s", rendered)
	}
}

func TestUpDashboardReconnectHeaderShowsDowntimeAndNotice(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	d, out := newTestUpDashboard(now)

	d.HandleLog("app", slog.LevelInfo, "tunnel ready", []slog.Attr{
		slog.String("public_url", "https://app.example.com"),
		slog.String("tunnel_id", "tun_1"),
	})

	now = now.Add(1 * time.Second)
	d.nowFunc = func() time.Time { return now }
	d.HandleLog("app", slog.LevelWarn, "client disconnected; reconnecting", []slog.Attr{
		slog.String("err", "connection lost"),
	})

	now = now.Add(3 * time.Second)
	d.nowFunc = func() time.Time { return now }
	out.Reset()
	d.HandleLog("app", slog.LevelWarn, "tunnel register failed", []slog.Attr{
		slog.String("err", "connection refused"),
	})
	rendered := out.String()

	if !strings.Contains(rendered, "Session") || !strings.Contains(rendered, "reconnecting") {
		t.Fatalf("expected reconnecting session state, got: %s", rendered)
	}
	if !strings.Contains(rendered, "downtime 3 seconds") {
		t.Fatalf("expected reconnect downtime details, got: %s", rendered)
	}
	if !strings.Contains(rendered, "tunnel register failed: connection refused") {
		t.Fatalf("expected reconnect notice in header, got: %s", rendered)
	}

	sessionIdx := strings.Index(rendered, "Session")
	detailsIdx := strings.Index(rendered, "downtime 3 seconds")
	noticeIdx := strings.Index(rendered, "tunnel register failed: connection refused")
	serverIdx := strings.Index(rendered, "Server")
	if sessionIdx < 0 || detailsIdx <= sessionIdx || noticeIdx <= detailsIdx || serverIdx <= noticeIdx {
		t.Fatalf("expected session, details, notice, then server order, got: %s", rendered)
	}
}

func TestUpDashboardReconnectClearsAutoDetailsAndNoticeWhenOnline(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	d, out := newTestUpDashboard(now)

	d.HandleLog("app", slog.LevelInfo, "tunnel ready", []slog.Attr{
		slog.String("public_url", "https://app.example.com"),
		slog.String("tunnel_id", "tun_1"),
	})

	now = now.Add(2 * time.Second)
	d.nowFunc = func() time.Time { return now }
	d.HandleLog("app", slog.LevelWarn, "client disconnected; reconnecting", []slog.Attr{
		slog.String("err", "connection lost"),
	})
	d.HandleLog("app", slog.LevelWarn, "tunnel register failed", []slog.Attr{
		slog.String("err", "connection refused"),
	})

	now = now.Add(2 * time.Second)
	d.nowFunc = func() time.Time { return now }
	out.Reset()
	d.HandleLog("app", slog.LevelInfo, "tunnel ready", []slog.Attr{
		slog.String("public_url", "https://app.example.com"),
		slog.String("tunnel_id", "tun_1"),
	})
	rendered := out.String()

	if strings.Contains(rendered, "downtime") {
		t.Fatalf("expected reconnect downtime details to clear when online, got: %s", rendered)
	}
	if strings.Contains(rendered, "tunnel register failed") {
		t.Fatalf("expected reconnect notice to clear when online, got: %s", rendered)
	}
}

func TestUpDashboardFormatDowntime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		d    time.Duration
		want string
	}{
		{1500 * time.Millisecond, "1 second"},
		{59*time.Second + 900*time.Millisecond, "59 seconds"},
		{60 * time.Second, "1 minute"},
		{62 * time.Second, "1 minute"},
		{2*time.Minute + 59*time.Second, "2 minutes"},
	}
	for _, tt := range tests {
		if got := displayFormatDowntime(tt.d); got != tt.want {
			t.Fatalf("displayFormatDowntime(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestUpDashboardReconnectDetailsShowCumulativeDowntime(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	d, out := newTestUpDashboard(now)

	d.HandleLog("app", slog.LevelInfo, "tunnel ready", []slog.Attr{
		slog.String("public_url", "https://app.example.com"),
		slog.String("tunnel_id", "tun_1"),
	})

	now = now.Add(10 * time.Second)
	d.nowFunc = func() time.Time { return now }
	d.HandleLog("app", slog.LevelWarn, "client disconnected; reconnecting", []slog.Attr{
		slog.String("err", "connection lost"),
	})

	now = now.Add(20 * time.Second)
	d.nowFunc = func() time.Time { return now }
	d.HandleLog("app", slog.LevelInfo, "tunnel ready", []slog.Attr{
		slog.String("public_url", "https://app.example.com"),
		slog.String("tunnel_id", "tun_1"),
	})

	now = now.Add(10 * time.Second)
	d.nowFunc = func() time.Time { return now }
	d.HandleLog("app", slog.LevelWarn, "client disconnected; reconnecting", []slog.Attr{
		slog.String("err", "connection lost"),
	})

	now = now.Add(3 * time.Second)
	d.nowFunc = func() time.Time { return now }
	out.Reset()
	d.HandleLog("app", slog.LevelWarn, "tunnel register failed", []slog.Attr{
		slog.String("err", "connection refused"),
	})
	rendered := out.String()

	if !strings.Contains(rendered, "downtime 23 seconds") {
		t.Fatalf("expected reconnect details to show cumulative downtime, got: %s", rendered)
	}
}

func TestUpDashboardForwardingWrapsLocalTargetOnNarrowTerminal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	d, out := newTestUpDashboard(now)
	d.terminalColumnsFn = func() int { return 60 }

	publicURL := "https://very-long-subdomain.example.com"
	localTarget := "http://localhost:3000"
	cacheKey, _, ok := upLocalTargetDialAddr(localTarget)
	if !ok {
		t.Fatal("expected valid local target")
	}
	d.localHealth[cacheKey] = upDashboardLocalHealth{OK: true, CheckedAt: now}
	d.groups["app"].PublicURL = publicURL

	out.Reset()
	d.mu.Lock()
	d.redrawLocked()
	d.mu.Unlock()
	rendered := out.String()

	firstLine := "Forwarding" + strings.Repeat(" ", upDisplayFieldWidth-len("Forwarding")) + publicURL
	secondLine := strings.Repeat(" ", upDisplayFieldWidth) + "→ " + localTarget + " ●"

	if !strings.Contains(rendered, firstLine) {
		t.Fatalf("expected forwarding URL on the labeled row, got: %s", rendered)
	}
	if !strings.Contains(rendered, secondLine) {
		t.Fatalf("expected wrapped forwarding target on aligned continuation row, got: %s", rendered)
	}
}
