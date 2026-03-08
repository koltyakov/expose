package traffic

import (
	"testing"
	"time"
)

func TestMeterSnapshotAndRollingWindow(t *testing.T) {
	t.Parallel()

	meter := NewMeter(time.Second)
	base := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)

	meter.AddAt(base, DirectionInbound, 512)
	meter.AddAt(base.Add(400*time.Millisecond), DirectionInbound, 256)
	meter.AddAt(base.Add(500*time.Millisecond), DirectionOutbound, 1024)

	snap := meter.SnapshotAt(base.Add(900 * time.Millisecond))
	if snap.InboundTotal != 768 {
		t.Fatalf("expected inbound total 768, got %d", snap.InboundTotal)
	}
	if snap.OutboundTotal != 1024 {
		t.Fatalf("expected outbound total 1024, got %d", snap.OutboundTotal)
	}
	if snap.InboundRate != 768 {
		t.Fatalf("expected inbound rate 768, got %d", snap.InboundRate)
	}
	if snap.OutboundRate != 1024 {
		t.Fatalf("expected outbound rate 1024, got %d", snap.OutboundRate)
	}

	snap = meter.SnapshotAt(base.Add(1300 * time.Millisecond))
	if snap.InboundTotal != 768 {
		t.Fatalf("expected inbound total to persist, got %d", snap.InboundTotal)
	}
	if snap.OutboundTotal != 1024 {
		t.Fatalf("expected outbound total to persist, got %d", snap.OutboundTotal)
	}
	if snap.InboundRate != 256 {
		t.Fatalf("expected inbound rate 256 after prune, got %d", snap.InboundRate)
	}
	if snap.OutboundRate != 1024 {
		t.Fatalf("expected outbound rate 1024 after prune, got %d", snap.OutboundRate)
	}

	snap = meter.SnapshotAt(base.Add(2501 * time.Millisecond))
	if snap.InboundRate != 0 {
		t.Fatalf("expected inbound rate 0 after window expiry, got %d", snap.InboundRate)
	}
	if snap.OutboundRate != 0 {
		t.Fatalf("expected outbound rate 0 after window expiry, got %d", snap.OutboundRate)
	}
}

func TestFormatTotalAndRate(t *testing.T) {
	t.Parallel()

	if got := FormatTotalAndRate(0, 0); got != "0 B total (0 B/s)" {
		t.Fatalf("unexpected zero formatting: %q", got)
	}
	if got := FormatTotalAndRate(1536, 2048); got != "1.5 KB total (2 KB/s)" {
		t.Fatalf("unexpected formatted summary: %q", got)
	}
}
