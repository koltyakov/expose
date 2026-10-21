# Performance testing

## Complete tunnel benchmarks

```bash
go test ./internal/client -run '^$' -bench '^BenchmarkTunnelEndToEnd$' -benchmem -benchtime=3s -count=5
```

This benchmark starts the production server, registers a real tunnel, runs the
production client session and local forwarding code, and sends concurrent public
HTTPS requests through it. WAF is enabled. Public requests use HTTP/2 over TLS;
tunnel traffic uses TLS WebSocket or HTTP/3 multi-stream v2. Only certificate
verification for the generated loopback certificate is disabled.

The cases serve 8 KiB and 1 MiB responses. Output includes allocations and
end-to-end p95/p99 latency in milliseconds, sampled from the last 8,192 completed
requests. Go's `ns/op` is aggregate concurrent throughput cost, not request
latency. Setup, registration, and shutdown are outside the timed region.

Optional process-heap sampling:

```bash
EXPOSE_E2E_SAMPLE_HEAP=true go test ./internal/client -run '^$' -bench '^BenchmarkTunnelEndToEnd$' -benchmem -benchtime=3s -count=1
```

`peak_heap_delta_B` is the largest sampled Go heap allocation above the warm
baseline. Samples run every 10 ms and include both endpoints in one process.
This is not peak RSS or per-request memory. Sampling perturbs latency, so run
allocation/latency comparisons separately without it.

## Focused benchmarks

```bash
go test ./internal/server -run '^$' -bench '^BenchmarkRouteCacheFullFreshChurn$' -benchmem -count=5
go test ./internal/client -run '^$' -bench '^BenchmarkForwardAndSendParallel$' -benchmem -count=5
go test ./internal/server -run '^$' -bench '^BenchmarkPublishedManifest$' -benchmem -count=5
```

The cache benchmark keeps 100, 10,000, or 100,000 fresh entries at capacity and
inserts new hosts. It exercises eviction rather than only cache hits. Eviction
examines at most eight entries, then uses a separate miss index to avoid
evicting a hit when a negative entry is available.

On an Apple M4 Pro with Go 1.27.2, the median of three 500 ms samples compared
the cache implementation at `8d36623` with the bounded implementation, using
the same fresh-cache churn benchmark:

| Fresh entries | Previous eviction | Bounded eviction |
| --- | --- | --- |
| 100 | 3.39 µs/op | 0.52 µs/op |
| 10,000 | 202 µs/op | 0.59 µs/op |
| 100,000 | 6.38 ms/op | 1.28 µs/op |

This measures insertion into a full cache, not overall tunnel throughput. Cache
hits and live-route lookups do not run eviction.

Small-response forwarding benchmarks accept both inline and streamed delivery.
Scheduling can exceed the 25 ms inline window under load; that is valid behavior,
not a benchmark failure. They validate status, byte count, and clean stream end.

The manifest benchmark compares hashing and encoding a 100-file publication with
retrieving its cached encoded file list. It excludes authentication and network
writes, so the cached result is not an API round-trip latency.

The [transport matrix report](benchmark.md) uses synthetic tunnel responders.
It remains useful for isolating server and codec costs, but excludes the real
client's HTTP forwarding path. Do not treat its request cost as full user latency.
Its checked-in measurements also refer to the commit and toolchain listed there.

## Failure and network testing

```bash
go test -race ./internal/client ./internal/server -run 'Test.*(WritePump|Budget|ActiveStream|Inactivity|Upload|Deadlines)' -count=5
```

Regression tests cover QUIC v2 connection churn, rejected WebSocket admission,
active streams exceeding their timeout, stalled upstreams, immediate upload
headers/chunks, queue budget cleanup, and unrelated requests continuing after a
slow consumer exhausts its budget.

Loopback results do not establish a preferred transport on a WAN. Compare separate
client/server processes on a test Linux host or network namespace with controlled
RTT, bandwidth, and packet loss, for example through `tc netem`. Apply shaping only
to the test interfaces. Include mixed small requests, large transfers, slow
readers, and reconnect bursts. Record p95/p99, errors, RSS, goroutines, and queue
rejections, not just throughput. No network shaping or host configuration changes
are performed by the Go benchmarks.

For CPU and allocation profiles, add `-cpuprofile=cpu.out` or
`-memprofile=heap.out` to a focused benchmark invocation, then inspect with
`go tool pprof`. Keep payload sizes, concurrency, Go version, and machine load
consistent when comparing revisions.

## Existing microbenchmarks and soak runs

`make bench` runs the server, client, SQLite, and protocol suites, including the
complete-tunnel benchmark above. Useful narrower commands remain:

```bash
go test ./internal/server -bench 'PublicHTTPRoundTrip' -run '^$' -benchmem
go test ./internal/client -bench 'Forward(Local|AndSend)' -run '^$' -benchmem
go test ./internal/store/sqlite ./internal/tunnelproto -bench . -run '^$' -benchmem
go test ./internal/tunnelproto -bench 'Phase1VsPhase2PacketLossMixedLoad' -run '^$'
go test ./internal/tunnelproto -bench 'CompatibilityModeWSVsH3Stream' -run '^$'
go test ./internal/server -bench 'PublicHTTPRoundTripTransportMatrix' -run '^$' -benchmem
```

The protocol packet-loss simulation compares codec behavior. It does not model
the complete TCP/QUIC stacks and cannot replace WAN measurements.

`make bench-transport` refreshes the heavy synthetic transport matrix in
[benchmark.md](benchmark.md), covering up to 200 tunnels with 10, 25, 50, or 100
requests per tunnel. Formatting that report requires `prettier` on `PATH`, or
`npx` and Node.js.

For multi-tunnel connection capacity and reconnect churn against a running
server:

```bash
expose soak --port 3000 --count 200 --duration 10m
expose soak --port 3000 --count 200 --duration 10m --churn-interval 30s --churn-batch 10
```

Use `EXPOSE_PPROF_LISTEN=127.0.0.1:6060` on either process for live profiles at
`/debug/pprof/`. The server also exposes `/debug/metrics` on that listener.
These endpoints have no application authentication. Keep them on loopback or
restrict network access.

Save a baseline before changing code. Compare sequential and parallel results
before raising concurrency limits. Recheck SQLite mutation latency after
disconnect or touch batching changes. Use soak runs and live profiles to confirm
that higher throughput does not hide growing heap, goroutine, or reconnect costs.
