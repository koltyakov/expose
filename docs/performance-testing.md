# Performance Testing

Repeatable benchmarks now cover the hot tunnel paths on both the server and client sides.

For live diagnosis, you can also enable `pprof` on either process with `EXPOSE_PPROF_LISTEN=127.0.0.1:6060` and inspect `/debug/pprof/` while a load or soak run is active.

## Run Everything

```bash
make bench
```

That runs the focused benchmark suites in:

- `internal/server` for public HTTP tunnel round-trips, parallel load, and streamed responses
- `internal/client` for local forward costs and streamed-response forwarding
- `internal/store/sqlite` for token and route-store operations
- `internal/tunnelproto` for protocol encoding/decoding

## Useful Narrow Runs

Server public tunnel path:

```bash
go test ./internal/server -bench 'PublicHTTPRoundTrip' -run '^$'
```

Client forward path:

```bash
go test ./internal/client -bench 'Forward(Local|AndSend)' -run '^$'
```

Store and protocol microbenchmarks:

```bash
go test ./internal/store/sqlite ./internal/tunnelproto -bench . -run '^$'
```

Multi-tunnel connection soak:

```bash
expose soak --port 3000 --count 200 --duration 10m
```

Soak with churn:

```bash
expose soak --port 3000 --count 200 --duration 10m --churn-interval 30s --churn-batch 10
```

## What the New Server Benchmarks Cover

- Single connected tunnel serving small HTTP responses
- Parallel HTTP requests over one active tunnel
- Streamed responses that exceed the inline body threshold
- Many client sessions in one process, with optional restart churn

These are single-node measurements. They are useful for vertical-scaling decisions, regressions, and tuning values such as `EXPOSE_MAX_PENDING_PER_TUNNEL`, `EXPOSE_MAX_CONCURRENT_FORWARDS`, and SQLite pool sizes.

## How to Read the Results

- Use `ns/op` and `B/op` to spot regressions after protocol or buffering changes.
- Watch streamed-response benchmarks after changing chunk sizes or websocket write behavior.
- Compare sequential and parallel tunnel results before raising concurrency caps; if parallel performance flattens early, the bottleneck is usually websocket serialization or the local upstream, not route lookup.
- Use the soak runner to validate peak connected tunnels and reconnect behavior; use `pprof` during the run if active counts flatten unexpectedly or heap growth looks suspicious.

## Suggested Workflow

1. Run `make bench` on the main branch and save the output.
2. Re-run after transport, buffering, or timeout changes.
3. If a benchmark regresses materially, run `go test -bench ... -cpuprofile cpu.out -memprofile mem.out` on the affected package before changing limits.
