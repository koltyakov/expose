package turnrelay

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRelayLogDowngradesPeerCloseNoise(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logFactory{slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))}.NewLogger("turn")
	logger.Errorf("Failed to close conn: %s", "tls: failed to send closeNotify alert (but connection was closed anyway): write tcp4 192.0.2.1:5349->198.51.100.2:1: write: broken pipe")
	logger.Error("Failed to close conn: write: connection reset by peer")
	if buf.Len() != 0 {
		t.Fatalf("peer close noise logged: %s", buf.String())
	}
	logger.Error("Failed to close conn: permission denied")
	logger.Error("allocation failed")
	if got := strings.Count(buf.String(), "level=ERROR"); got != 2 {
		t.Fatalf("real errors logged %d times, want 2: %s", got, buf.String())
	}
}
