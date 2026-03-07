package client

import (
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestClientTrackWSOpenAndCloseDisplay(t *testing.T) {
	t.Parallel()

	d, buf := newTestDisplay(false)
	d.ShowBanner("dev")

	c := &Client{display: d}
	open := &tunnelproto.WSOpen{
		ID:    "ws_1",
		Path:  "/ws",
		Query: "room=alpha",
		Headers: map[string][]string{
			"X-Forwarded-For": {"1.2.3.4"},
			"User-Agent":      {"Browser/1.0"},
		},
	}

	buf.Reset()
	c.trackWSOpen(open.ID, open)
	out := buf.String()
	if !strings.Contains(out, "1 open") {
		t.Fatalf("expected websocket counter to increment, got: %s", out)
	}
	if !strings.Contains(out, "1 active, 1 total") {
		t.Fatalf("expected websocket visitor to count as active client, got: %s", out)
	}
	if got := d.wsConns[open.ID].path; got != "/ws?room=alpha" {
		t.Fatalf("expected websocket path with query to be tracked, got %q", got)
	}

	c.trackWSClose(open.ID)
	buf.Reset()
	d.mu.Lock()
	d.wsDisplayMin = 0
	d.redraw()
	d.mu.Unlock()
	out = buf.String()
	if !strings.Contains(out, "WebSockets") {
		t.Fatalf("expected websocket field to remain visible, got: %s", out)
	}
	if strings.Contains(out, "1 open") {
		t.Fatalf("expected websocket counter to clear after close, got: %s", out)
	}
	if !strings.Contains(out, "--") {
		t.Fatalf("expected websocket placeholder after close, got: %s", out)
	}
}
