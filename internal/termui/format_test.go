package termui

import (
	"testing"
	"time"
)

func TestCapitalizeCSV(t *testing.T) {
	t.Parallel()

	got := CapitalizeCSV("alpha, beta,,gamma")
	want := "Alpha, Beta, , Gamma"
	if got != want {
		t.Fatalf("CapitalizeCSV() = %q, want %q", got, want)
	}
}

func TestFormatDurationRounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input time.Duration
		want  string
	}{
		{input: 999 * time.Microsecond, want: "999μs"},
		{input: 250 * time.Millisecond, want: "250ms"},
		{input: 1500 * time.Millisecond, want: "1.50s"},
	}

	for _, tt := range tests {
		if got := FormatDurationRounded(tt.input); got != tt.want {
			t.Fatalf("FormatDurationRounded(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatDowntime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input time.Duration
		want  string
	}{
		{input: -5 * time.Second, want: "0 seconds"},
		{input: 59*time.Second + 800*time.Millisecond, want: "59 seconds"},
		{input: 2*time.Minute + 12*time.Second, want: "2 minutes"},
		{input: 3 * time.Hour, want: "3 hours"},
		{input: 3*time.Hour + 2*time.Minute, want: "3 hours, 2 minutes"},
	}

	for _, tt := range tests {
		if got := FormatDowntime(tt.input); got != tt.want {
			t.Fatalf("FormatDowntime(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestPluralize(t *testing.T) {
	t.Parallel()

	if got := Pluralize(1, "request"); got != "request" {
		t.Fatalf("Pluralize(1) = %q, want %q", got, "request")
	}
	if got := Pluralize(2, "request"); got != "requests" {
		t.Fatalf("Pluralize(2) = %q, want %q", got, "requests")
	}
}

func TestFormatLatencyPercentiles(t *testing.T) {
	t.Parallel()

	samples := []time.Duration{
		100 * time.Millisecond,
		10 * time.Millisecond,
		90 * time.Millisecond,
		50 * time.Millisecond,
	}

	got, ok := FormatLatencyPercentiles(samples, FormatDurationRounded)
	if !ok {
		t.Fatal("FormatLatencyPercentiles() ok = false, want true")
	}

	want := LatencyPercentiles{
		P50: "50ms",
		P90: "100ms",
		P95: "100ms",
		P99: "100ms",
	}
	if got != want {
		t.Fatalf("FormatLatencyPercentiles() = %#v, want %#v", got, want)
	}
}

func TestFormatLatencyPercentilesEmpty(t *testing.T) {
	t.Parallel()

	if _, ok := FormatLatencyPercentiles(nil, FormatDurationRounded); ok {
		t.Fatal("FormatLatencyPercentiles(nil) ok = true, want false")
	}
}

func TestDurationPercentile(t *testing.T) {
	t.Parallel()

	sorted := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
	}

	tests := []struct {
		p    int
		want time.Duration
	}{
		{p: -1, want: 10 * time.Millisecond},
		{p: 0, want: 10 * time.Millisecond},
		{p: 1, want: 10 * time.Millisecond},
		{p: 50, want: 20 * time.Millisecond},
		{p: 100, want: 30 * time.Millisecond},
		{p: 101, want: 30 * time.Millisecond},
	}

	for _, tt := range tests {
		if got := DurationPercentile(sorted, tt.p); got != tt.want {
			t.Fatalf("DurationPercentile(%v, %d) = %v, want %v", sorted, tt.p, got, tt.want)
		}
	}

	if got := DurationPercentile(nil, 50); got != 0 {
		t.Fatalf("DurationPercentile(nil, 50) = %v, want 0", got)
	}
}
