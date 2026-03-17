package cli

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/traffic"
)

func TestUpDashboardHandlerHelpers(t *testing.T) {
	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	d, _ := newTestUpDashboard(now)

	h := &upDashboardHandler{
		ui:        d,
		subdomain: "app",
		level:     slog.LevelWarn,
		attrs:     []slog.Attr{slog.String("tunnel_id", "tun_1")},
	}

	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("Enabled(info) = true, want false")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("Enabled(error) = false, want true")
	}

	withAttrs := h.WithAttrs([]slog.Attr{slog.String("public_url", "https://app.example.com")}).(*upDashboardHandler)
	withGroup := withAttrs.WithGroup("ignored").(*upDashboardHandler)

	rec := slog.NewRecord(now, slog.LevelError, "tunnel ready", 0)
	rec.AddAttrs(slog.String("public_url", "https://app.example.com"))
	if err := withGroup.Handle(context.Background(), rec); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if got := d.groups["app"].TunnelID; got != "tun_1" {
		t.Fatalf("TunnelID = %q, want %q", got, "tun_1")
	}
	if got := d.groups["app"].PublicURL; got != "https://app.example.com" {
		t.Fatalf("PublicURL = %q, want %q", got, "https://app.example.com")
	}

	if err := (&upDashboardHandler{}).Handle(context.Background(), rec); err != nil {
		t.Fatalf("Handle(nil ui) error = %v", err)
	}

	logger := d.Logger("app")
	logger.Info("versions", "server", "v1.2.3")
	if got := d.serverVersions["app"]; got != "v1.2.3" {
		t.Fatalf("Logger().Info() stored %q, want %q", got, "v1.2.3")
	}
}

func TestUpDashboardAttrHelpers(t *testing.T) {
	t.Parallel()

	attrs := flattenSlogAttrs([]slog.Attr{
		slog.String("string", " value "),
		slog.Int("int", 12),
		slog.Int64("int64", 34),
		slog.String("intstr", "56"),
		slog.String("int64str", "78"),
		slog.Bool("bool", true),
		slog.String("boolstr", "yes"),
		{},
	})

	if got := attrString(attrs, "string"); got != "value" {
		t.Fatalf("attrString() = %q, want %q", got, "value")
	}
	if got := attrInt(attrs, "int"); got != 12 {
		t.Fatalf("attrInt(int) = %d, want 12", got)
	}
	if got := attrInt(attrs, "intstr"); got != 56 {
		t.Fatalf("attrInt(string) = %d, want 56", got)
	}
	if got := attrInt64(attrs, "int64"); got != 34 {
		t.Fatalf("attrInt64(int64) = %d, want 34", got)
	}
	if got := attrInt64(attrs, "int64str"); got != 78 {
		t.Fatalf("attrInt64(string) = %d, want 78", got)
	}
	if !attrBool(attrs, "bool") || !attrBool(attrs, "boolstr") {
		t.Fatal("attrBool() = false, want true")
	}
	if attrBool(attrs, "missing") {
		t.Fatal("attrBool(missing) = true, want false")
	}
}

func TestUpDashboardAggregateHelpers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	d := newUpDashboard("expose.yml", "dev")
	d.nowFunc = func() time.Time { return now }
	d.order = []string{"a", "b"}
	d.groups = map[string]*upDashboardGroup{
		"a": {Status: "online"},
		"b": {Status: "reconnecting"},
	}

	if got := d.aggregateStatusLocked(); got != "reconnecting" {
		t.Fatalf("aggregateStatusLocked() = %q, want %q", got, "reconnecting")
	}
	d.groups["b"].Status = "error"
	if got := d.aggregateStatusLocked(); got != "error" {
		t.Fatalf("aggregateStatusLocked(error) = %q, want %q", got, "error")
	}

	d.serverVersions = map[string]string{"a": "v1", "b": "v1", "c": "v2"}
	if got := d.serverVersionDisplayLocked(); got != "v1, v2" {
		t.Fatalf("serverVersionDisplayLocked() = %q, want %q", got, "v1, v2")
	}

	d.tlsModes = map[string]string{"a": "dynamic", "c": "wildcard"}
	if got := d.joinMapValuesLocked(d.tlsModes); got != "dynamic, wildcard" {
		t.Fatalf("joinMapValuesLocked() = %q, want %q", got, "dynamic, wildcard")
	}

	d.wafEnabled = map[string]bool{"a": false, "b": true}
	if !d.anyWAFEnabledLocked() {
		t.Fatal("anyWAFEnabledLocked() = false, want true")
	}
}

func TestUpDashboardRequestAndLatencyHelpers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	d, _ := newTestUpDashboard(now)

	d.appendRequestLocked(upDashboardRequest{
		At:       now,
		Method:   "GET",
		Path:     "/health",
		Status:   200,
		Duration: "1500ms",
	})
	if len(d.reqs) != 1 {
		t.Fatalf("len(reqs) = %d, want 1", len(d.reqs))
	}
	if len(d.latencySamples) != 1 || d.latencySamples[0] != 1500*time.Millisecond {
		t.Fatalf("latencySamples = %#v", d.latencySamples)
	}

	d.appendLatencySampleLocked(-5 * time.Millisecond)
	for i := range upLatencySampleMax + 2 {
		d.appendLatencySampleLocked(time.Duration(i+1) * time.Millisecond)
	}
	if len(d.latencySamples) != upLatencySampleMax {
		t.Fatalf("len(latencySamples) = %d, want %d", len(d.latencySamples), upLatencySampleMax)
	}
	if d.latencySamples[0] < 0 {
		t.Fatalf("latencySamples[0] = %v, want non-negative", d.latencySamples[0])
	}
}

func TestUpDashboardRouteAndVisitorHelpers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	d, _ := newTestUpDashboard(now)
	d.order = []string{"app", "api"}
	d.groups["api"] = &upDashboardGroup{Subdomain: "api"}

	if got := d.requestDisplayPathLocked(upDashboardRequest{Subdomain: "app", Path: "/health"}); got != "app /health" {
		t.Fatalf("requestDisplayPathLocked() = %q, want %q", got, "app /health")
	}

	d.touchVisitorLocked(" user-1 ")
	d.visitors["stale"] = now.Add(-2 * upActiveClientWindow)
	d.wsConns["app|1"] = upDashboardWS{Fingerprint: "socket-user"}
	if got := d.activeClientCountLocked(); got != 2 {
		t.Fatalf("activeClientCountLocked() = %d, want 2", got)
	}
}

func TestUpDashboardTrackWSCloseLocked(t *testing.T) {
	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	d, _ := newTestUpDashboard(now)
	d.wsConns["app|1"] = upDashboardWS{Subdomain: "app", StreamID: "1"}

	d.trackWSCloseLocked("app|1")
	if d.wsDisplayMin != 1 {
		t.Fatalf("wsDisplayMin = %d, want 1", d.wsDisplayMin)
	}

	deadline := time.Now().Add(upWSCloseDebounce + 500*time.Millisecond)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		done := d.wsDisplayMin == 0 && d.wsDebounceTimer == nil
		d.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ws close debounce did not reset display floor")
}

func TestUpDashboardFormattingHelpers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	d, _ := newTestUpDashboard(now)

	if got := d.formatRequestStatusText(200); !strings.Contains(got, "200 OK") {
		t.Fatalf("formatRequestStatusText(200) = %q", got)
	}
	if got := d.formatRequestStatusText(302); !strings.Contains(got, "302 Found") {
		t.Fatalf("formatRequestStatusText(302) = %q", got)
	}
	if got := d.formatRequestStatusText(404); !strings.Contains(got, "404 Not Found") {
		t.Fatalf("formatRequestStatusText(404) = %q", got)
	}
	if got := d.formatRequestStatusText(500); !strings.Contains(got, "500 Internal Server Error") {
		t.Fatalf("formatRequestStatusText(500) = %q", got)
	}

	if got := dashboardFormatRequestDuration(" 1500μs "); got != "1ms" {
		t.Fatalf("dashboardFormatRequestDuration() = %q, want %q", got, "1ms")
	}
	if got, ok := dashboardParseRequestDuration("-1s"); !ok || got != 0 {
		t.Fatalf("dashboardParseRequestDuration(-1s) = %v, %v", got, ok)
	}
	if got := dashboardFormatDurationRounded(1500 * time.Millisecond); got != "1.50s" {
		t.Fatalf("dashboardFormatDurationRounded() = %q, want %q", got, "1.50s")
	}

	if got := upFormatHeaderUptime(25*time.Hour + 2*time.Minute); got != "1 day, 1 hour, 2 minutes" {
		t.Fatalf("upFormatHeaderUptime() = %q", got)
	}

	d.statusText = "reconnecting"
	d.startedAt = now.Add(-time.Hour)
	d.pendingDisconnectAt = now.Add(-10 * time.Second)
	d.sessionDowntime = 20 * time.Second
	d.sessionDisconnects = 1
	if got := d.sessionStatsDetailLocked(now); !strings.Contains(got, "downtime 30 seconds") || !strings.Contains(got, "2 disconnects") {
		t.Fatalf("sessionStatsDetailLocked() = %q", got)
	}

	d.noticeText = "warning"
	d.noticeLevel = "warn"
	if got := d.noticeDisplayTextLocked(); got != "warning" {
		t.Fatalf("noticeDisplayTextLocked(warn,color-off) = %q, want %q", got, "warning")
	}
	if got := pluralizeUpUnit(2, "disconnect"); got != "disconnects" {
		t.Fatalf("pluralizeUpUnit() = %q, want %q", got, "disconnects")
	}
	if got := displayFormatDowntime(2 * time.Minute); got != "2 minutes" {
		t.Fatalf("displayFormatDowntime() = %q, want %q", got, "2 minutes")
	}

	if vals, ok := upLatencyPercentiles([]time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond}); !ok || vals.p50 == "" {
		t.Fatalf("upLatencyPercentiles() = %#v, %v", vals, ok)
	}
}

func TestUpDashboardMiscHelpers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	d, _ := newTestUpDashboard(now)

	if d.now().IsZero() {
		t.Fatal("now() returned zero time")
	}

	meter := d.trafficMeterLocked("app")
	if meter == nil || d.trafficMeterLocked("app") != meter {
		t.Fatal("trafficMeterLocked() did not reuse existing meter")
	}
	meter.AddAt(now, traffic.DirectionInbound, 1024)
	snapshot := d.aggregateTrafficSnapshotLocked()
	if snapshot.InboundTotal != 1024 {
		t.Fatalf("aggregateTrafficSnapshotLocked() = %#v", snapshot)
	}
	if got := d.trafficSummaryText(snapshot); !strings.Contains(got, "In 1 KB total") {
		t.Fatalf("trafficSummaryText() = %q", got)
	}

	if got := dashboardLevelLabel(slog.LevelError); got != "ERROR" {
		t.Fatalf("dashboardLevelLabel(error) = %q, want ERROR", got)
	}
	if got := summarizeDashboardEvent("tunnel register failed", map[string]slog.Value{"err": slog.StringValue("connection refused")}); !strings.Contains(got, "connection refused") {
		t.Fatalf("summarizeDashboardEvent() = %q", got)
	}
	if got := shortenDashboardText("  too    much   space  ", 80); got != "too much space" {
		t.Fatalf("shortenDashboardText() = %q", got)
	}
	if got := upCapitalizeCSV("dynamic, wildcard"); got != "Dynamic, Wildcard" {
		t.Fatalf("upCapitalizeCSV() = %q", got)
	}
}
