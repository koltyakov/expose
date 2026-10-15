package traffic

import (
	"fmt"
	"math/rand/v2"
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

// referenceMeter is the original shift-on-every-prune implementation, kept to
// check that the amortized pruning reports exactly the same snapshots.
type referenceMeter struct {
	window                      time.Duration
	samples                     []sample
	inboundTotal, outboundTotal int64
	inboundRate, outboundRate   int64
}

func (m *referenceMeter) addAt(now time.Time, direction Direction, bytes int64) {
	s := sample{at: now}
	switch direction {
	case DirectionInbound:
		s.inbound = bytes
		m.inboundTotal += bytes
		m.inboundRate += bytes
	case DirectionOutbound:
		s.outbound = bytes
		m.outboundTotal += bytes
		m.outboundRate += bytes
	}
	m.samples = append(m.samples, s)
	m.prune(now)
}

func (m *referenceMeter) snapshotAt(now time.Time) Snapshot {
	m.prune(now)
	return Snapshot{
		InboundTotal:  m.inboundTotal,
		OutboundTotal: m.outboundTotal,
		InboundRate:   m.inboundRate,
		OutboundRate:  m.outboundRate,
	}
}

func (m *referenceMeter) prune(now time.Time) {
	cutoff := now.Add(-m.window)
	drop := 0
	for drop < len(m.samples) && m.samples[drop].at.Before(cutoff) {
		m.inboundRate -= m.samples[drop].inbound
		m.outboundRate -= m.samples[drop].outbound
		drop++
	}
	copy(m.samples, m.samples[drop:])
	m.samples = m.samples[:len(m.samples)-drop]
}

func TestMeterMatchesReferencePruning(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewPCG(1, 2))
	meter := NewMeter(time.Second)
	ref := &referenceMeter{window: time.Second}
	now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	for i := range 200_000 {
		// Mix bursts of same-instant reads, steady traffic, and idle gaps
		// that expire the whole window.
		switch r := rng.IntN(1000); {
		case r < 2:
			now = now.Add(time.Duration(1+rng.IntN(3000)) * time.Millisecond)
		case r < 500:
			now = now.Add(time.Duration(rng.IntN(200)) * time.Microsecond)
		}
		if rng.IntN(10) == 0 {
			if got, want := meter.SnapshotAt(now), ref.snapshotAt(now); got != want {
				t.Fatalf("step %d: snapshot = %+v, want %+v", i, got, want)
			}
			continue
		}
		direction := DirectionInbound
		if rng.IntN(2) == 0 {
			direction = DirectionOutbound
		}
		bytes := int64(1 + rng.IntN(64*1024))
		meter.AddAt(now, direction, bytes)
		ref.addAt(now, direction, bytes)
	}
	if live := len(meter.samples) - meter.head; live != len(ref.samples) {
		t.Fatalf("live samples = %d, want %d", live, len(ref.samples))
	}
	if expired, live := meter.head, len(meter.samples)-meter.head; expired*4 > live {
		t.Fatalf("expired prefix %d exceeds a quarter of live samples %d", expired, live)
	}
}

// BenchmarkMeterAddSteadyState measures one recorded read once the rolling
// window is full. Every body read on a forwarded request records a sample, so
// the window holds one entry per read in the last second.
func BenchmarkMeterAddSteadyState(b *testing.B) {
	for _, perWindow := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("samples=%d", perWindow), func(b *testing.B) {
			m := NewMeter(time.Second)
			step := time.Second / time.Duration(perWindow)
			now := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
			for range perWindow {
				now = now.Add(step)
				m.AddAt(now, DirectionOutbound, 32*1024)
			}

			b.ReportAllocs()
			for b.Loop() {
				now = now.Add(step)
				m.AddAt(now, DirectionOutbound, 32*1024)
			}
		})
	}
}
