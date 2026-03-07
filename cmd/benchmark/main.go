package main

import (
	"bytes"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const transportMatrixBenchCasesEnv = "EXPOSE_TRANSPORT_MATRIX_CASES"

var benchmarkLinePattern = regexp.MustCompile(`^BenchmarkPublicHTTPRoundTripTransportMatrix/(ws|quic)_tunnels_(\d+)_requests_per_tunnel_(\d+)-\d+\s+\d+\s+([0-9.]+) ns/op\s+([0-9.]+) MB/s\s+([0-9.]+) B/op\s+([0-9.]+) allocs/op$`)

var benchmarkScenarios = []scenarioConfig{
	{Tunnels: 25, RequestsPerTunnel: 10},
	{Tunnels: 25, RequestsPerTunnel: 25},
	{Tunnels: 25, RequestsPerTunnel: 50},
	{Tunnels: 25, RequestsPerTunnel: 100},
	{Tunnels: 50, RequestsPerTunnel: 10},
	{Tunnels: 50, RequestsPerTunnel: 25},
	{Tunnels: 50, RequestsPerTunnel: 50},
	{Tunnels: 50, RequestsPerTunnel: 100},
	{Tunnels: 100, RequestsPerTunnel: 10},
	{Tunnels: 100, RequestsPerTunnel: 25},
	{Tunnels: 100, RequestsPerTunnel: 50},
	{Tunnels: 100, RequestsPerTunnel: 100},
	{Tunnels: 200, RequestsPerTunnel: 10},
	{Tunnels: 200, RequestsPerTunnel: 25},
	{Tunnels: 200, RequestsPerTunnel: 50},
	{Tunnels: 200, RequestsPerTunnel: 100},
}

type scenarioKey struct {
	Tunnels           int
	RequestsPerTunnel int
	Transport         string
}

type scenarioConfig struct {
	Tunnels           int
	RequestsPerTunnel int
}

type sample struct {
	NsPerOp     float64
	MBPerSec    float64
	BytesPerOp  float64
	AllocsPerOp float64
}

type summary struct {
	Samples        int
	NsPerOpAvg     float64
	MBPerSecAvg    float64
	BytesPerOpAvg  float64
	AllocsPerOpAvg float64
}

type comparisonRow struct {
	Tunnels           int
	RequestsPerTunnel int
	TotalRequests     int
	WS                summary
	QUIC              summary
}

func main() {
	var (
		outputPath = flag.String("output", "docs/benchmark.md", "markdown report output path")
		samples    = flag.Int("samples", 5, "number of benchmark samples per scenario")
	)
	flag.Parse()

	if *samples <= 0 {
		exitf("samples must be > 0")
	}

	parsed, env, err := collectSamples(*samples)
	if err != nil {
		exitf("%v", err)
	}

	rows, err := buildComparisons(parsed)
	if err != nil {
		exitf("build benchmark summary: %v", err)
	}

	goVersion, _ := runCommand(nil, "go", "version")
	gitCommit, _ := runCommand(nil, "git", "rev-parse", "--short", "HEAD")
	gitStatus, _ := runCommand(nil, "git", "status", "--short")

	report := renderMarkdown(markdownInput{
		Now:         time.Now(),
		Command:     "EXPOSE_TRANSPORT_MATRIX_CASES=<tunnels>x<requests> go test ./internal/server -run ^$ -bench ^BenchmarkPublicHTTPRoundTripTransportMatrix$ -benchmem -benchtime 1x -count 1",
		Rows:        rows,
		Environment: env,
		GoVersion:   strings.TrimSpace(string(goVersion)),
		GitCommit:   strings.TrimSpace(string(gitCommit)),
		GitDirty:    strings.TrimSpace(string(gitStatus)) != "",
		Samples:     *samples,
	})

	if err := os.MkdirAll(filepath.Dir(*outputPath), 0o755); err != nil {
		exitf("create output directory: %v", err)
	}
	if err := os.WriteFile(*outputPath, []byte(report), 0o644); err != nil {
		exitf("write report: %v", err)
	}
	if err := formatMarkdown(*outputPath); err != nil {
		exitf("format report: %v", err)
	}

	fmt.Printf("wrote %s\n", *outputPath)
}

func runCommand(extraEnv []string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd.CombinedOutput()
}

func formatMarkdown(path string) error {
	args := []string{"--write", "--parser", "markdown", path}
	name := "prettier"
	if _, err := exec.LookPath(name); err != nil {
		name = "npx"
		args = append([]string{"--yes", "prettier"}, args...)
		if _, npxErr := exec.LookPath(name); npxErr != nil {
			return fmt.Errorf("prettier not found in PATH and npx is unavailable")
		}
	}
	output, err := runCommand(nil, name, args...)
	if err != nil {
		return fmt.Errorf("%s %s failed: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func collectSamples(samplesPerScenario int) (map[scenarioKey][]sample, benchmarkEnv, error) {
	parsed := make(map[scenarioKey][]sample)
	var env benchmarkEnv

	for _, scenario := range benchmarkScenarios {
		for _, transport := range []string{"ws", "quic"} {
			key := scenarioKey{
				Tunnels:           scenario.Tunnels,
				RequestsPerTunnel: scenario.RequestsPerTunnel,
				Transport:         transport,
			}
			maxAttempts := samplesPerScenario * 3
			var lastOutput []byte
			var lastErr error
			for attempts := 0; len(parsed[key]) < samplesPerScenario && attempts < maxAttempts; attempts++ {
				output, runErr := runTransportBenchmark(key)
				lastOutput = output
				lastErr = runErr

				runParsed, runEnv, parseErr := parseBenchmarkOutput(output)
				if parseErr != nil {
					return nil, env, fmt.Errorf("parse benchmark output for %+v: %w\n\n%s", key, parseErr, string(output))
				}
				env = mergeEnv(env, runEnv)
				if samples := runParsed[key]; len(samples) > 0 {
					parsed[key] = append(parsed[key], samples[0])
				}
			}
			if len(parsed[key]) < samplesPerScenario {
				return nil, env, fmt.Errorf(
					"collected %d/%d samples for %+v; last error: %v\n\n%s",
					len(parsed[key]),
					samplesPerScenario,
					key,
					lastErr,
					string(lastOutput),
				)
			}
		}
	}

	return parsed, env, nil
}

func runTransportBenchmark(key scenarioKey) ([]byte, error) {
	benchPattern := fmt.Sprintf(
		"^BenchmarkPublicHTTPRoundTripTransportMatrix/%s_tunnels_%d_requests_per_tunnel_%d$",
		key.Transport,
		key.Tunnels,
		key.RequestsPerTunnel,
	)
	extraEnv := []string{
		fmt.Sprintf("%s=%dx%d", transportMatrixBenchCasesEnv, key.Tunnels, key.RequestsPerTunnel),
	}
	return runCommand(
		extraEnv,
		"go",
		"test",
		"./internal/server",
		"-run",
		"^$",
		"-bench",
		benchPattern,
		"-benchmem",
		"-benchtime",
		"1x",
		"-count",
		"1",
	)
}

func parseBenchmarkOutput(output []byte) (map[scenarioKey][]sample, benchmarkEnv, error) {
	parsed := make(map[scenarioKey][]sample)
	var env benchmarkEnv

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "goos: "):
			env.GoOS = strings.TrimSpace(strings.TrimPrefix(line, "goos: "))
		case strings.HasPrefix(line, "goarch: "):
			env.GoArch = strings.TrimSpace(strings.TrimPrefix(line, "goarch: "))
		case strings.HasPrefix(line, "cpu: "):
			env.CPU = strings.TrimSpace(strings.TrimPrefix(line, "cpu: "))
		}

		matches := benchmarkLinePattern.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}

		tunnels, err := strconv.Atoi(matches[2])
		if err != nil {
			return nil, env, fmt.Errorf("parse tunnels from %q: %w", line, err)
		}
		requestsPerTunnel, err := strconv.Atoi(matches[3])
		if err != nil {
			return nil, env, fmt.Errorf("parse requests_per_tunnel from %q: %w", line, err)
		}
		nsPerOp, err := strconv.ParseFloat(matches[4], 64)
		if err != nil {
			return nil, env, fmt.Errorf("parse ns/op from %q: %w", line, err)
		}
		mbPerSec, err := strconv.ParseFloat(matches[5], 64)
		if err != nil {
			return nil, env, fmt.Errorf("parse MB/s from %q: %w", line, err)
		}
		bytesPerOp, err := strconv.ParseFloat(matches[6], 64)
		if err != nil {
			return nil, env, fmt.Errorf("parse B/op from %q: %w", line, err)
		}
		allocsPerOp, err := strconv.ParseFloat(matches[7], 64)
		if err != nil {
			return nil, env, fmt.Errorf("parse allocs/op from %q: %w", line, err)
		}

		key := scenarioKey{
			Tunnels:           tunnels,
			RequestsPerTunnel: requestsPerTunnel,
			Transport:         matches[1],
		}
		parsed[key] = append(parsed[key], sample{
			NsPerOp:     nsPerOp,
			MBPerSec:    mbPerSec,
			BytesPerOp:  bytesPerOp,
			AllocsPerOp: allocsPerOp,
		})
	}

	return parsed, env, nil
}

func buildComparisons(parsed map[scenarioKey][]sample) ([]comparisonRow, error) {
	index := make(map[[2]int]comparisonRow)
	for key, samples := range parsed {
		if len(samples) == 0 {
			return nil, fmt.Errorf("scenario %v has no samples", key)
		}
		rowKey := [2]int{key.Tunnels, key.RequestsPerTunnel}
		row := index[rowKey]
		row.Tunnels = key.Tunnels
		row.RequestsPerTunnel = key.RequestsPerTunnel
		row.TotalRequests = key.Tunnels * key.RequestsPerTunnel
		switch key.Transport {
		case "ws":
			row.WS = summarize(samples)
		case "quic":
			row.QUIC = summarize(samples)
		default:
			return nil, fmt.Errorf("unknown transport %q", key.Transport)
		}
		index[rowKey] = row
	}

	rows := make([]comparisonRow, 0, len(index))
	for _, row := range index {
		if row.WS.Samples == 0 || row.QUIC.Samples == 0 {
			return nil, fmt.Errorf("scenario tunnels=%d requests_per_tunnel=%d is missing one transport", row.Tunnels, row.RequestsPerTunnel)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Tunnels != rows[j].Tunnels {
			return rows[i].Tunnels < rows[j].Tunnels
		}
		return rows[i].RequestsPerTunnel < rows[j].RequestsPerTunnel
	})
	return rows, nil
}

func summarize(samples []sample) summary {
	var out summary
	out.Samples = len(samples)
	for _, sample := range samples {
		out.NsPerOpAvg += sample.NsPerOp
		out.MBPerSecAvg += sample.MBPerSec
		out.BytesPerOpAvg += sample.BytesPerOp
		out.AllocsPerOpAvg += sample.AllocsPerOp
	}
	divisor := float64(out.Samples)
	out.NsPerOpAvg /= divisor
	out.MBPerSecAvg /= divisor
	out.BytesPerOpAvg /= divisor
	out.AllocsPerOpAvg /= divisor
	return out
}

type benchmarkEnv struct {
	GoOS   string
	GoArch string
	CPU    string
}

func mergeEnv(current, next benchmarkEnv) benchmarkEnv {
	if current.GoOS == "" {
		current.GoOS = next.GoOS
	}
	if current.GoArch == "" {
		current.GoArch = next.GoArch
	}
	if current.CPU == "" {
		current.CPU = next.CPU
	}
	return current
}

type markdownInput struct {
	Now         time.Time
	Command     string
	Rows        []comparisonRow
	Environment benchmarkEnv
	GoVersion   string
	GitCommit   string
	GitDirty    bool
	Samples     int
}

func renderMarkdown(input markdownInput) string {
	var buf bytes.Buffer

	buf.WriteString("# Benchmark Report\n\n")
	buf.WriteString("Generated by `go run ./cmd/benchmark`. Re-run the command to refresh this file after code changes.\n\n")
	buf.WriteString("The runner executes each transport/scenario sample in a fresh `go test` process so repeated runs stay stable on loopback. The heavy matrix lives in `cmd/benchmark`, while `internal/server` keeps only a small default benchmark set unless `EXPOSE_TRANSPORT_MATRIX_CASES` is provided. Each scenario measures `10`, `25`, `50`, or `100` requests per tunnel and uses about one requester worker per two tunnels, capped at `100`.\n\n")

	buf.WriteString("## How To Read It\n\n")
	buf.WriteString("| Metric | Better | Meaning |\n")
	buf.WriteString("| --- | --- | --- |\n")
	buf.WriteString("| Sweep ms | Smaller | Time to finish one full sweep of all requests in the scenario. |\n")
	buf.WriteString("| Req/s | Larger | Completed public HTTP requests per second for the full sweep. |\n")
	buf.WriteString("| us/request | Smaller | Average wall-clock cost per request within the sweep. |\n")
	buf.WriteString("| KiB/request | Smaller | Heap bytes allocated per request. |\n")
	buf.WriteString("| allocs/request | Smaller | Heap allocations per request. |\n\n")

	buf.WriteString("## Environment\n\n")
	buf.WriteString("| Field | Value |\n")
	buf.WriteString("| --- | --- |\n")
	buf.WriteString(fmt.Sprintf("| Generated | %s |\n", input.Now.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("| Git commit | `%s` |\n", safeValue(input.GitCommit)))
	buf.WriteString(fmt.Sprintf("| Git dirty | `%t` |\n", input.GitDirty))
	buf.WriteString(fmt.Sprintf("| Go | `%s` |\n", safeValue(input.GoVersion)))
	buf.WriteString(fmt.Sprintf("| GOOS/GOARCH | `%s/%s` |\n", safeValue(input.Environment.GoOS), safeValue(input.Environment.GoArch)))
	buf.WriteString(fmt.Sprintf("| CPU | `%s` |\n", safeValue(input.Environment.CPU)))
	buf.WriteString(fmt.Sprintf("| Samples per scenario | `%d` |\n", input.Samples))
	buf.WriteString(fmt.Sprintf("| Command | `%s` |\n\n", input.Command))

	buf.WriteString("## Latency And Throughput\n\n")
	buf.WriteString("| Tunnels | Req/tunnel | Total req | WS sweep ms | QUIC sweep ms | Faster (smaller) | WS req/s | QUIC req/s | Faster (larger) |\n")
	buf.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, row := range input.Rows {
		wsSweepMs := row.WS.NsPerOpAvg / 1e6
		quicSweepMs := row.QUIC.NsPerOpAvg / 1e6
		wsReqPerSec := requestsPerSecond(row.TotalRequests, row.WS.NsPerOpAvg)
		quicReqPerSec := requestsPerSecond(row.TotalRequests, row.QUIC.NsPerOpAvg)
		buf.WriteString(fmt.Sprintf(
			"| %d | %d | %d | %s | %s | %s | %s | %s | %s |\n",
			row.Tunnels,
			row.RequestsPerTunnel,
			row.TotalRequests,
			formatFloat(wsSweepMs, 2),
			formatFloat(quicSweepMs, 2),
			lowerIsBetterWinner("WS", wsSweepMs, "QUIC", quicSweepMs),
			formatFloat(wsReqPerSec, 0),
			formatFloat(quicReqPerSec, 0),
			higherIsBetterWinner("WS", wsReqPerSec, "QUIC", quicReqPerSec),
		))
	}
	buf.WriteString("\n")

	buf.WriteString("## Request Cost\n\n")
	buf.WriteString("| Tunnels | WS us/request | QUIC us/request | Smaller | WS KiB/request | QUIC KiB/request | Smaller | WS allocs/request | QUIC allocs/request | Smaller |\n")
	buf.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, row := range input.Rows {
		wsUsPerRequest := row.WS.NsPerOpAvg / float64(row.TotalRequests) / 1e3
		quicUsPerRequest := row.QUIC.NsPerOpAvg / float64(row.TotalRequests) / 1e3
		wsKiBPerRequest := row.WS.BytesPerOpAvg / float64(row.TotalRequests) / 1024
		quicKiBPerRequest := row.QUIC.BytesPerOpAvg / float64(row.TotalRequests) / 1024
		wsAllocsPerRequest := row.WS.AllocsPerOpAvg / float64(row.TotalRequests)
		quicAllocsPerRequest := row.QUIC.AllocsPerOpAvg / float64(row.TotalRequests)
		buf.WriteString(fmt.Sprintf(
			"| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			row.Tunnels,
			formatFloat(wsUsPerRequest, 2),
			formatFloat(quicUsPerRequest, 2),
			lowerIsBetterWinner("WS", wsUsPerRequest, "QUIC", quicUsPerRequest),
			formatFloat(wsKiBPerRequest, 2),
			formatFloat(quicKiBPerRequest, 2),
			lowerIsBetterWinner("WS", wsKiBPerRequest, "QUIC", quicKiBPerRequest),
			formatFloat(wsAllocsPerRequest, 2),
			formatFloat(quicAllocsPerRequest, 2),
			lowerIsBetterWinner("WS", wsAllocsPerRequest, "QUIC", quicAllocsPerRequest),
		))
	}

	return buf.String()
}

func requestsPerSecond(totalRequests int, nsPerOp float64) float64 {
	if totalRequests <= 0 || nsPerOp <= 0 {
		return 0
	}
	return float64(totalRequests) / (nsPerOp / float64(time.Second))
}

func lowerIsBetterWinner(leftLabel string, left float64, rightLabel string, right float64) string {
	switch {
	case nearlyEqual(left, right):
		return "Tie"
	case left < right:
		return leftLabel
	default:
		return rightLabel
	}
}

func higherIsBetterWinner(leftLabel string, left float64, rightLabel string, right float64) string {
	switch {
	case nearlyEqual(left, right):
		return "Tie"
	case left > right:
		return leftLabel
	default:
		return rightLabel
	}
}

func nearlyEqual(left, right float64) bool {
	if left == right {
		return true
	}
	diff := math.Abs(left - right)
	scale := math.Max(math.Abs(left), math.Abs(right))
	if scale == 0 {
		return diff == 0
	}
	return diff/scale < 0.005
}

func formatFloat(value float64, digits int) string {
	return strconv.FormatFloat(value, 'f', digits, 64)
}

func safeValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
