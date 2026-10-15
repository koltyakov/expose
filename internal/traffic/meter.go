package traffic

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const DefaultWindow = time.Second

type Direction uint8

const (
	DirectionInbound Direction = iota + 1
	DirectionOutbound
)

type Snapshot struct {
	InboundTotal  int64
	OutboundTotal int64
	InboundRate   int64
	OutboundRate  int64
}

type Meter struct {
	mu     sync.Mutex
	window time.Duration
	// samples[head:] are the samples still inside the window. Expired samples
	// are skipped by advancing head and compacted away in batches, so pruning
	// stays amortized O(1) per recorded sample.
	samples       []sample
	head          int
	inboundTotal  int64
	outboundTotal int64
	inboundRate   int64
	outboundRate  int64
}

type sample struct {
	at       time.Time
	inbound  int64
	outbound int64
}

func NewMeter(window time.Duration) *Meter {
	if window <= 0 {
		window = DefaultWindow
	}
	return &Meter{window: window}
}

func (m *Meter) Add(direction Direction, bytes int64) {
	m.AddAt(time.Now(), direction, bytes)
}

func (m *Meter) AddAt(now time.Time, direction Direction, bytes int64) {
	if m == nil || bytes <= 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

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
	default:
		return
	}
	m.samples = append(m.samples, s)
	m.pruneLocked(now)
}

func (m *Meter) Snapshot() Snapshot {
	return m.SnapshotAt(time.Now())
}

func (m *Meter) SnapshotAt(now time.Time) Snapshot {
	if m == nil {
		return Snapshot{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.pruneLocked(now)
	return Snapshot{
		InboundTotal:  m.inboundTotal,
		OutboundTotal: m.outboundTotal,
		InboundRate:   m.inboundRate,
		OutboundRate:  m.outboundRate,
	}
}

func (m *Meter) pruneLocked(now time.Time) {
	if m.head == len(m.samples) {
		return
	}
	cutoff := now.Add(-m.window)
	head := m.head
	for head < len(m.samples) && m.samples[head].at.Before(cutoff) {
		m.inboundRate -= m.samples[head].inbound
		m.outboundRate -= m.samples[head].outbound
		head++
	}
	if head == m.head {
		return
	}
	m.head = head
	// Every body read records a sample, so shifting the whole window on each
	// prune made a busy transfer cost O(window) per read under the lock.
	// Compacting once a quarter of the live samples have expired copies each
	// sample at most four times and keeps the slack below a quarter.
	if expired, live := head, len(m.samples)-head; expired*4 >= live {
		copy(m.samples, m.samples[head:])
		m.samples = m.samples[:live]
		m.head = 0
	}
}

func CombineSnapshots(items ...Snapshot) Snapshot {
	var out Snapshot
	for _, item := range items {
		out.InboundTotal += item.InboundTotal
		out.OutboundTotal += item.OutboundTotal
		out.InboundRate += item.InboundRate
		out.OutboundRate += item.OutboundRate
	}
	return out
}

func FormatTotalAndRate(total, rate int64) string {
	return fmt.Sprintf("%s total (%s)", FormatBytes(total), FormatRate(rate))
}

func FormatRate(rate int64) string {
	return FormatBytes(rate) + "/s"
}

func FormatBytes(bytes int64) string {
	if bytes < 0 {
		bytes = 0
	}
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}

	value := float64(bytes)
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	return formatFloat(value) + " " + units[unit]
}

func formatFloat(v float64) string {
	switch {
	case v >= 100:
		return fmt.Sprintf("%.0f", v)
	case v >= 10:
		return fmt.Sprintf("%.1f", v)
	default:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".")
	}
}
