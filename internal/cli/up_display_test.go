package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/traffic"
)

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
