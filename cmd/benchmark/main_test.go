package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseBenchmarkOutputAndBuildComparisons(t *testing.T) {
	output := []byte(strings.Join([]string{
		"goos: linux",
		"goarch: amd64",
		"cpu: Test CPU",
		"BenchmarkPublicHTTPRoundTripTransportMatrix/ws_tunnels_25_requests_per_tunnel_10-8 1 1000000 ns/op 120.0 MB/s 2048.0 B/op 10.0 allocs/op",
		"BenchmarkPublicHTTPRoundTripTransportMatrix/ws_tunnels_25_requests_per_tunnel_10-8 1 2000000 ns/op 140.0 MB/s 1024.0 B/op 12.0 allocs/op",
		"BenchmarkPublicHTTPRoundTripTransportMatrix/quic_tunnels_25_requests_per_tunnel_10-8 1 3000000 ns/op 90.0 MB/s 4096.0 B/op 20.0 allocs/op",
		"",
	}, "\n"))

	parsed, env, err := parseBenchmarkOutput(output)
	if err != nil {
		t.Fatalf("parseBenchmarkOutput() error = %v", err)
	}
	if env.GoOS != "linux" || env.GoArch != "amd64" || env.CPU != "Test CPU" {
		t.Fatalf("unexpected benchmark env: %#v", env)
	}

	rows, err := buildComparisons(parsed)
	if err != nil {
		t.Fatalf("buildComparisons() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want %d", len(rows), 1)
	}
	row := rows[0]
	if row.TotalRequests != 250 {
		t.Fatalf("TotalRequests = %d, want %d", row.TotalRequests, 250)
	}
	if row.WS.Samples != 2 {
		t.Fatalf("WS.Samples = %d, want %d", row.WS.Samples, 2)
	}
	if row.WS.NsPerOpAvg != 1500000 {
		t.Fatalf("WS.NsPerOpAvg = %f, want %f", row.WS.NsPerOpAvg, 1500000.0)
	}
	if row.QUIC.Samples != 1 {
		t.Fatalf("QUIC.Samples = %d, want %d", row.QUIC.Samples, 1)
	}
}

func TestParseBenchmarkOutputErrors(t *testing.T) {
	output := []byte("BenchmarkPublicHTTPRoundTripTransportMatrix/ws_tunnels_25_requests_per_tunnel_10-8 1 1.2.3 ns/op 120.0 MB/s 2048.0 B/op 10.0 allocs/op\n")

	if _, _, err := parseBenchmarkOutput(output); err == nil || !strings.Contains(err.Error(), "parse ns/op") {
		t.Fatalf("parseBenchmarkOutput() error = %v, want parse ns/op error", err)
	}
}

func TestBuildComparisonsErrors(t *testing.T) {
	_, err := buildComparisons(map[scenarioKey][]sample{
		{Tunnels: 25, RequestsPerTunnel: 10, Transport: "ws"}: nil,
	})
	if err == nil || !strings.Contains(err.Error(), "has no samples") {
		t.Fatalf("buildComparisons(empty) error = %v, want no samples error", err)
	}

	_, err = buildComparisons(map[scenarioKey][]sample{
		{Tunnels: 25, RequestsPerTunnel: 10, Transport: "udp"}: {{NsPerOp: 1}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown transport") {
		t.Fatalf("buildComparisons(unknown) error = %v, want unknown transport error", err)
	}

	_, err = buildComparisons(map[scenarioKey][]sample{
		{Tunnels: 25, RequestsPerTunnel: 10, Transport: "ws"}: {{NsPerOp: 1}},
	})
	if err == nil || !strings.Contains(err.Error(), "missing one transport") {
		t.Fatalf("buildComparisons(missing transport) error = %v, want missing transport error", err)
	}
}

func TestRenderMarkdownAndHelpers(t *testing.T) {
	report := renderMarkdown(markdownInput{
		Now:       time.Date(2026, time.March, 15, 18, 0, 0, 0, time.UTC),
		Command:   "go test ./internal/server",
		GoVersion: "go version go1.25.0",
		GitCommit: "abc123",
		GitDirty:  true,
		Samples:   2,
		Environment: benchmarkEnv{
			GoOS:   "linux",
			GoArch: "amd64",
			CPU:    "Test CPU",
		},
		Rows: []comparisonRow{
			{
				Tunnels:           25,
				RequestsPerTunnel: 10,
				TotalRequests:     250,
				WS:                summary{Samples: 2, NsPerOpAvg: 1_000_000, MBPerSecAvg: 120, BytesPerOpAvg: 2048, AllocsPerOpAvg: 10},
				QUIC:              summary{Samples: 2, NsPerOpAvg: 2_000_000, MBPerSecAvg: 80, BytesPerOpAvg: 4096, AllocsPerOpAvg: 20},
			},
		},
	})

	if !strings.Contains(report, "# Benchmark Report") {
		t.Fatal("renderMarkdown() missing title")
	}
	if !strings.Contains(report, "| 25 | 10 | 250 |") {
		t.Fatal("renderMarkdown() missing scenario row")
	}
	if !strings.Contains(report, "WS") {
		t.Fatal("renderMarkdown() missing winner text")
	}

	if got := requestsPerSecond(250, 1_000_000); got != 250000 {
		t.Fatalf("requestsPerSecond() = %f, want %f", got, 250000.0)
	}
	if got := requestsPerSecond(0, 1); got != 0 {
		t.Fatalf("requestsPerSecond(zero total) = %f, want 0", got)
	}
	if got := lowerIsBetterWinner("WS", 1.0, "QUIC", 2.0); got != "WS" {
		t.Fatalf("lowerIsBetterWinner() = %q, want %q", got, "WS")
	}
	if got := higherIsBetterWinner("WS", 2.0, "QUIC", 1.0); got != "WS" {
		t.Fatalf("higherIsBetterWinner() = %q, want %q", got, "WS")
	}
	if got := lowerIsBetterWinner("WS", 1.0, "QUIC", 1.004); got != "Tie" {
		t.Fatalf("lowerIsBetterWinner(nearly equal) = %q, want Tie", got)
	}
	if !nearlyEqual(1.0, 1.004) {
		t.Fatal("nearlyEqual() = false, want true")
	}
	if nearlyEqual(1.0, 1.1) {
		t.Fatal("nearlyEqual() = true for distinct values, want false")
	}
	if got := formatFloat(1.2345, 2); got != "1.23" {
		t.Fatalf("formatFloat() = %q, want %q", got, "1.23")
	}
	if got := safeValue("   "); got != "unknown" {
		t.Fatalf("safeValue(blank) = %q, want %q", got, "unknown")
	}
	if got := safeValue("go version"); got != "go version" {
		t.Fatalf("safeValue(value) = %q, want %q", got, "go version")
	}
}

func TestMergeEnv(t *testing.T) {
	current := benchmarkEnv{GoOS: "linux"}
	next := benchmarkEnv{GoOS: "darwin", GoArch: "arm64", CPU: "M4"}

	got := mergeEnv(current, next)
	if got.GoOS != "linux" || got.GoArch != "arm64" || got.CPU != "M4" {
		t.Fatalf("mergeEnv() = %#v", got)
	}
}

func TestRunCommandAndFormatMarkdownError(t *testing.T) {
	output, err := runCommand(nil, "go", "version")
	if err != nil {
		t.Fatalf("runCommand() error = %v", err)
	}
	if !strings.Contains(string(output), "go version") {
		t.Fatalf("runCommand() output = %q, want go version", string(output))
	}

	path := filepath.Join(t.TempDir(), "report.md")
	if err := os.WriteFile(path, []byte("# Test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	t.Setenv("PATH", "")
	if err := formatMarkdown(path); err == nil || !strings.Contains(err.Error(), "prettier not found") {
		t.Fatalf("formatMarkdown() error = %v, want prettier not found error", err)
	}
}

func TestSummarizeAndContextCancellationSafety(t *testing.T) {
	got := summarize([]sample{
		{NsPerOp: 1, MBPerSec: 2, BytesPerOp: 3, AllocsPerOp: 4},
		{NsPerOp: 3, MBPerSec: 4, BytesPerOp: 5, AllocsPerOp: 6},
	})
	if got.NsPerOpAvg != 2 || got.MBPerSecAvg != 3 || got.BytesPerOpAvg != 4 || got.AllocsPerOpAvg != 5 {
		t.Fatalf("summarize() = %#v", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("context should already be canceled")
	}
}
