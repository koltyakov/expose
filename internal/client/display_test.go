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
	d := &Display{out: &buf, color: color, wsConns: make(map[string]wsEntry), visitors: make(map[string]struct{})}
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
	if strings.Contains(out, "TLS Mode") {
		t.Fatal("expected no TLS Mode field when empty")
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

	buf.Reset()
	d.TrackWSClose("ws_1")
	d.TrackWSClose("ws_2")
	// Reset and trigger a redraw to get clean final state.
	buf.Reset()
	d.ShowInfo("sync")
	out = buf.String()
	// After all WS closed, "WebSockets" field should not appear.
	if strings.Contains(out, "WebSockets") {
		t.Fatal("expected no WebSockets field after all closed")
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
}
