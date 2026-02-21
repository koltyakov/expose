package client

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func newTestDisplay(color bool) (*Display, *bytes.Buffer) {
	var buf bytes.Buffer
	d := &Display{out: &buf, color: color, wsConns: make(map[string]wsEntry), visitors: make(map[string]time.Time), nowFunc: time.Now}
	return d, &buf
}

func TestDisplayBannerNoColor(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("v1.0.0")
	out := buf.String()
	if !strings.Contains(out, "expose") {
		t.Fatal("expected banner to contain 'expose'")
	}
	if !strings.Contains(out, "v1.0.0") {
		t.Fatal("expected banner to contain version")
	}
	if !strings.Contains(out, "Ctrl+C") {
		t.Fatal("expected banner to contain quit hint")
	}
	if strings.Contains(out, "\033[") {
		t.Fatal("expected no ANSI codes when color is off")
	}
}

func TestDisplayBannerColor(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(true)
	d.ShowBanner("dev")
	out := buf.String()
	if !strings.Contains(out, "\033[") {
		t.Fatal("expected ANSI codes when color is on")
	}
}

func TestDisplayTunnelInfo(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowTunnelInfo("https://myapp.example.com", "http://localhost:3000", "autocert", "tun_abc123")
	out := buf.String()
	if !strings.Contains(out, "online") {
		t.Fatal("expected 'online' status")
	}
	if !strings.Contains(out, "https://myapp.example.com") {
		t.Fatal("expected public URL")
	}
	if !strings.Contains(out, "http://localhost:3000") {
		t.Fatal("expected local address")
	}
	if !strings.Contains(out, "autocert") {
		t.Fatal("expected TLS mode")
	}
	if !strings.Contains(out, "tun_abc123") {
		t.Fatal("expected tunnel ID")
	}
	if !strings.Contains(out, "HTTP Requests") {
		t.Fatal("expected HTTP Requests header")
	}
	if !strings.Contains(out, "Clients") {
		t.Fatal("expected Clients counter")
	}
}

func TestDisplayTunnelInfoNoTLSMode(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowTunnelInfo("https://app.example.com", "http://localhost:8080", "", "tun_xyz")
	out := buf.String()
	// TLS Mode field is always present; when empty it shows "--"
	if !strings.Contains(out, "TLS Mode") {
		t.Fatal("expected TLS Mode field to always be present")
	}
	if !strings.Contains(out, "--") {
		t.Fatal("expected '--' placeholder for empty TLS Mode")
	}
}

func TestDisplayLogRequest(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")
	d.LogRequest("GET", "/api/health", 200, 12*time.Millisecond, nil)
	out := buf.String()
	if !strings.Contains(out, "GET") {
		t.Fatal("expected method")
	}
	if !strings.Contains(out, "/api/health") {
		t.Fatal("expected path")
	}
	if !strings.Contains(out, "200") {
		t.Fatal("expected status code")
	}
	if !strings.Contains(out, "12ms") {
		t.Fatal("expected duration")
	}
}

func TestDisplayLogRequestMaxEntries(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	// Log 15 requests, only last 10 should survive.
	for i := 0; i < 15; i++ {
		d.LogRequest("GET", fmt.Sprintf("/req/%d", i), 200, time.Millisecond, nil)
	}

	// The last redraw is the final state. Since each redraw clears the
	// screen and rewrites, we check the final output by resetting the
	// buffer and triggering one more redraw.
	buf.Reset()
	d.LogRequest("GET", "/req/15", 200, time.Millisecond, nil) // triggers redraw
	out := buf.String()

	// Oldest entries (0..5) should be evicted, newest 10 (6..15) survive.
	if strings.Contains(out, "/req/0 ") || strings.Contains(out, "/req/4 ") || strings.Contains(out, "/req/5 ") {
		t.Fatal("expected old requests to be evicted")
	}
	for i := 6; i <= 15; i++ {
		want := fmt.Sprintf("/req/%d", i)
		if !strings.Contains(out, want) {
			t.Fatalf("expected recent request %q to be visible", want)
		}
	}
}

func TestDisplayLogRequestStatusColors(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(true)
	d.ShowBanner("dev")

	d.LogRequest("GET", "/ok", 200, time.Millisecond, nil)
	d.LogRequest("GET", "/redirect", 301, time.Millisecond, nil)
	d.LogRequest("GET", "/notfound", 404, time.Millisecond, nil)
	d.LogRequest("GET", "/error", 500, time.Millisecond, nil)

	out := buf.String()
	if !strings.Contains(out, ansiGreen+"200") {
		t.Fatal("expected green color for 200")
	}
	if !strings.Contains(out, ansiCyan+"301") {
		t.Fatal("expected cyan color for 301")
	}
	if !strings.Contains(out, ansiYellow+"404") {
		t.Fatal("expected yellow color for 404")
	}
	if !strings.Contains(out, ansiRed+"500") {
		t.Fatal("expected red color for 500")
	}
}

func TestDisplayReconnecting(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowReconnecting("connection lost")
	out := buf.String()
	if !strings.Contains(out, "reconnecting") {
		t.Fatal("expected reconnecting status")
	}
}

func TestDisplayWarningAndInfo(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowWarning("something went wrong")
	d.ShowInfo("just letting you know")
	out := buf.String()
	if !strings.Contains(out, "WARN") {
		t.Fatal("expected WARN label")
	}
	if !strings.Contains(out, "something went wrong") {
		t.Fatal("expected warning message")
	}
	if !strings.Contains(out, "INFO") {
		t.Fatal("expected INFO label")
	}
	if !strings.Contains(out, "just letting you know") {
		t.Fatal("expected info message")
	}
}

func TestDisplayWSTracking(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	d.TrackWSOpen("ws_1", "/chat", nil)
	buf.Reset()
	d.TrackWSOpen("ws_2", "/events", nil)
	out := buf.String()
	if !strings.Contains(out, "2 open") {
		t.Fatal("expected 2 open in WebSockets counter")
	}

	d.TrackWSClose("ws_1")
	d.TrackWSClose("ws_2")
	// Simulate the debounce timer expiring (clears the display floor).
	d.mu.Lock()
	d.wsDisplayMin = 0
	d.mu.Unlock()
	// Trigger a clean redraw after the floor is cleared.
	buf.Reset()
	d.ShowInfo("sync")
	out = buf.String()
	// After all WS closed and debounce expired, should show "--" placeholder.
	if !strings.Contains(out, "WebSockets") {
		t.Fatal("expected WebSockets field to always be present")
	}
	if !strings.Contains(out, "--") {
		t.Fatal("expected '--' placeholder for WebSockets after all closed")
	}
}

func TestDisplayTotalHTTPCounter(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	d.LogRequest("GET", "/a", 200, time.Millisecond, nil)
	d.LogRequest("POST", "/b", 201, time.Millisecond, nil)
	out := buf.String()
	if !strings.Contains(out, "2 total") {
		t.Fatal("expected 2 total requests")
	}
}

func TestDisplayWaitingMessage(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowTunnelInfo("https://app.example.com", "http://localhost:8080", "", "tun_xyz")
	out := buf.String()
	if !strings.Contains(out, "Waiting for requests") {
		t.Fatal("expected waiting message when no requests logged")
	}
}

func TestDisplayTruncatePath(t *testing.T) {
	t.Parallel()
	short := "/api"
	if got := displayTruncatePath(short, 40); got != short {
		t.Fatalf("expected %q, got %q", short, got)
	}
	long := "/api/v1/users/12345/settings/notifications/preferences"
	got := displayTruncatePath(long, 40)
	if len(got) != 40 {
		t.Fatalf("expected length 40, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatal("expected truncated path to end with ...")
	}
}

func TestDisplayFormatDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Microsecond, "500μs"},
		{12 * time.Millisecond, "12ms"},
		{1500 * time.Millisecond, "1.50s"},
	}
	for _, tt := range tests {
		if got := displayFormatDuration(tt.d); got != tt.want {
			t.Errorf("displayFormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestDisplayLogRequestUsesNowFuncTimestamp(t *testing.T) {
	t.Parallel()

	d, buf := newTestDisplay(false)
	fixed := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	d.nowFunc = func() time.Time { return fixed }
	d.ShowBanner("dev")

	buf.Reset()
	d.LogRequest("GET", "/clock", 200, 3*time.Millisecond, nil)
	out := buf.String()
	if !strings.Contains(out, "03:04:05") {
		t.Fatalf("expected request timestamp from nowFunc clock, got: %s", out)
	}
}

func TestFirstHeaderValueCI(t *testing.T) {
	t.Parallel()

	headers := map[string][]string{
		"X-Forwarded-For": {"1.2.3.4"},
		"uSeR-aGeNt":      {"Browser/1.0"},
	}
	if got := firstHeaderValueCI(headers, "X-Forwarded-For"); got != "1.2.3.4" {
		t.Fatalf("expected X-Forwarded-For value, got %q", got)
	}
	if got := firstHeaderValueCI(headers, "User-Agent"); got != "Browser/1.0" {
		t.Fatalf("expected case-insensitive User-Agent value, got %q", got)
	}
	if got := firstHeaderValueCI(headers, "X-Real-Ip"); got != "" {
		t.Fatalf("expected empty result for missing header, got %q", got)
	}
}

func TestDisplayCleanup(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(true)
	d.Cleanup()
	out := buf.String()
	if !strings.Contains(out, ansiShowCur) {
		t.Fatal("expected cursor restore on cleanup")
	}
}

func TestVisitorFingerprint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{"nil headers", nil, ""},
		{"empty headers", map[string][]string{}, ""},
		{"ip only", map[string][]string{"X-Forwarded-For": {"1.2.3.4"}}, "1.2.3.4|"},
		{"ip and ua", map[string][]string{
			"X-Forwarded-For": {"1.2.3.4"},
			"User-Agent":      {"Mozilla/5.0"},
		}, "1.2.3.4|Mozilla/5.0"},
		{"xff chain takes first", map[string][]string{"X-Forwarded-For": {"1.2.3.4, 5.6.7.8"}}, "1.2.3.4|"},
		{"x-real-ip fallback", map[string][]string{"X-Real-Ip": {"10.0.0.1"}}, "10.0.0.1|"},
		{"xff takes precedence over x-real-ip", map[string][]string{
			"X-Forwarded-For": {"1.2.3.4"},
			"X-Real-Ip":       {"10.0.0.1"},
		}, "1.2.3.4|"},
		{"case insensitive", map[string][]string{"x-forwarded-for": {"9.8.7.6"}}, "9.8.7.6|"},
		{"same ip different ua are different", map[string][]string{
			"X-Forwarded-For": {"1.2.3.4"},
			"User-Agent":      {"Chrome"},
		}, "1.2.3.4|Chrome"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := visitorFingerprint(tt.headers)
			if got != tt.want {
				t.Errorf("visitorFingerprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDisplayUniqueClients(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	h1 := map[string][]string{"X-Forwarded-For": {"1.2.3.4"}, "User-Agent": {"Chrome"}}
	h2 := map[string][]string{"X-Forwarded-For": {"5.6.7.8"}, "User-Agent": {"Firefox"}}

	d.LogRequest("GET", "/a", 200, time.Millisecond, h1)
	d.LogRequest("GET", "/b", 200, time.Millisecond, h1) // same IP+UA
	d.LogRequest("GET", "/c", 200, time.Millisecond, h2) // different IP+UA

	buf.Reset()
	d.LogRequest("GET", "/d", 200, time.Millisecond, nil) // no headers
	out := buf.String()

	if !strings.Contains(out, "2 total") {
		t.Fatal("expected 2 total clients")
	}
	if !strings.Contains(out, "2 active") {
		t.Fatal("expected 2 active clients (both within 60s window)")
	}
}

func TestDisplayUniqueClientsSameIPDifferentUA(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	h1 := map[string][]string{"X-Forwarded-For": {"1.2.3.4"}, "User-Agent": {"Chrome"}}
	h2 := map[string][]string{"X-Forwarded-For": {"1.2.3.4"}, "User-Agent": {"Firefox"}}

	d.LogRequest("GET", "/a", 200, time.Millisecond, h1)
	buf.Reset()
	d.LogRequest("GET", "/b", 200, time.Millisecond, h2) // same IP, different UA
	out := buf.String()

	if !strings.Contains(out, "2 total") {
		t.Fatal("expected 2 total clients for same IP with different User-Agents")
	}
}

func TestDisplayUniqueClientsFromWS(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	h := map[string][]string{"X-Forwarded-For": {"10.0.0.1"}}
	d.TrackWSOpen("ws_1", "/ws", h)

	buf.Reset()
	d.LogRequest("GET", "/api", 200, time.Millisecond, nil)
	out := buf.String()

	if !strings.Contains(out, "1 total") {
		t.Fatal("expected 1 total client from WebSocket")
	}
	if !strings.Contains(out, "1 active") {
		t.Fatal("expected 1 active client from WebSocket")
	}
}

func TestDisplayActiveClientsExpiry(t *testing.T) {
	t.Parallel()
	now := time.Now()
	d, buf := newTestDisplay(false)
	d.nowFunc = func() time.Time { return now }
	d.ShowBanner("dev")

	h1 := map[string][]string{"X-Forwarded-For": {"1.2.3.4"}, "User-Agent": {"Chrome"}}
	h2 := map[string][]string{"X-Forwarded-For": {"5.6.7.8"}, "User-Agent": {"Firefox"}}

	d.LogRequest("GET", "/a", 200, time.Millisecond, h1)
	d.LogRequest("GET", "/b", 200, time.Millisecond, h2)

	// Both visitors active now.
	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out := buf.String()
	if !strings.Contains(out, "2 active") {
		t.Fatal("expected 2 active clients initially")
	}

	// Advance time past the 60s window.
	now = now.Add(61 * time.Second)

	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out = buf.String()
	if !strings.Contains(out, "0 active") {
		t.Fatalf("expected 0 active clients after 61s, got: %s", out)
	}
	if !strings.Contains(out, "2 total") {
		t.Fatal("expected 2 total clients preserved")
	}
}

func TestDisplayActiveClientsWSKeepsAlive(t *testing.T) {
	t.Parallel()
	now := time.Now()
	d, buf := newTestDisplay(false)
	d.nowFunc = func() time.Time { return now }
	d.ShowBanner("dev")

	h := map[string][]string{"X-Forwarded-For": {"1.2.3.4"}, "User-Agent": {"Chrome"}}
	d.TrackWSOpen("ws_1", "/ws", h)

	// Advance past the 60s window.
	now = now.Add(120 * time.Second)

	// Visitor should still be active because the WebSocket is open.
	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out := buf.String()
	if !strings.Contains(out, "1 active") {
		t.Fatalf("expected 1 active from open WebSocket, got: %s", out)
	}

	// Close the WS — now with expired timestamp, visitor should become inactive.
	d.TrackWSClose("ws_1")
	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out = buf.String()
	if !strings.Contains(out, "0 active") {
		t.Fatalf("expected 0 active after WS close + expired window, got: %s", out)
	}
	if !strings.Contains(out, "1 total") {
		t.Fatal("expected 1 total client preserved")
	}
}

func TestDisplayPageRefreshKeepsActive(t *testing.T) {
	t.Parallel()
	now := time.Now()
	d, buf := newTestDisplay(false)
	d.nowFunc = func() time.Time { return now }
	d.ShowBanner("dev")

	h := map[string][]string{"X-Forwarded-For": {"1.2.3.4"}, "User-Agent": {"Chrome"}}

	// Simulate: visitor opens page (HTTP request + WebSocket).
	d.LogRequest("GET", "/", 200, time.Millisecond, h)
	d.TrackWSOpen("ws_1", "/ws", h)

	// 5 seconds later, visitor refreshes → WS closes, new HTTP request + WS opens.
	now = now.Add(5 * time.Second)
	d.TrackWSClose("ws_1")

	// Between close and new open, active count should still be 1 (within 60s window).
	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out := buf.String()
	if !strings.Contains(out, "1 active") {
		t.Fatalf("expected 1 active during page refresh gap, got: %s", out)
	}

	// New page load arrives.
	d.LogRequest("GET", "/", 200, time.Millisecond, h)
	d.TrackWSOpen("ws_2", "/ws", h)

	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out = buf.String()
	if !strings.Contains(out, "1 active") {
		t.Fatalf("expected 1 active after refresh, got: %s", out)
	}
}

func TestDisplayWSCloseDebounceNoBlink(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	// Open two WebSockets.
	d.TrackWSOpen("ws_1", "/chat", nil)
	d.TrackWSOpen("ws_2", "/events", nil)
	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out := buf.String()
	if !strings.Contains(out, "2 open") {
		t.Fatal("expected 2 open WebSockets initially")
	}

	// Close ws_1 — the floor holds the displayed count at 2.
	buf.Reset()
	d.TrackWSClose("ws_1")
	out = buf.String()
	// Counter should still show "2 open" thanks to the floor.
	if !strings.Contains(out, "2 open") {
		t.Fatalf("expected floor to keep counter at '2 open', got: %s", out)
	}

	// A new event (e.g. WS open) triggers an immediate redraw which absorbs
	// the previous close — the counter goes from 2 → 2 smoothly.
	buf.Reset()
	d.TrackWSOpen("ws_3", "/new", nil)
	out = buf.String()
	if !strings.Contains(out, "2 open") {
		t.Fatalf("expected 2 open after close+open, got: %s", out)
	}

	// After the debounce timer fires, the floor clears and the real count shows.
	d.mu.Lock()
	d.wsDisplayMin = 0
	d.mu.Unlock()
	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out = buf.String()
	if !strings.Contains(out, "2 open") {
		t.Fatalf("expected 2 open (ws_2 + ws_3 still open), got: %s", out)
	}

	// Close all remaining and clear floor.
	d.TrackWSClose("ws_2")
	d.TrackWSClose("ws_3")
	d.mu.Lock()
	d.wsDisplayMin = 0
	d.mu.Unlock()
	buf.Reset()
	d.mu.Lock()
	d.redraw()
	d.mu.Unlock()
	out = buf.String()
	if !strings.Contains(out, "--") {
		t.Fatalf("expected '--' after all WS closed and debounce expired, got: %s", out)
	}
}

func TestDisplayShowLatency(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")
	buf.Reset()

	d.ShowLatency(42 * time.Millisecond)
	out := buf.String()
	if !strings.Contains(out, "Latency") {
		t.Fatal("expected Latency label in output")
	}
	if !strings.Contains(out, "42ms") {
		t.Fatalf("expected '42ms' in output, got: %s", out)
	}
}

func TestDisplayLatencyHiddenWhenZero(t *testing.T) {
	t.Parallel()
	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")
	out := buf.String()
	// Latency field is always present; before any measurement it shows "--".
	if !strings.Contains(out, "Latency") {
		t.Fatal("expected Latency field to always be present")
	}
	if !strings.Contains(out, "--") {
		t.Fatal("expected '--' placeholder for Latency before any measurement")
	}
	buf.Reset()
}
