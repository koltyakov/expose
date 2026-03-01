# Performance Testing

Repeatable benchmarks now cover the hot tunnel paths on both the server and client sides.

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

## What the New Server Benchmarks Cover

- Single connected tunnel serving small HTTP responses
- Parallel HTTP requests over one active tunnel
- Streamed responses that exceed the inline body threshold

These are single-node measurements. They are useful for vertical-scaling decisions, regressions, and tuning values such as `EXPOSE_MAX_PENDING_PER_TUNNEL`, `EXPOSE_MAX_CONCURRENT_FORWARDS`, and SQLite pool sizes.

## How to Read the Results

- Use `ns/op` and `B/op` to spot regressions after protocol or buffering changes.
- Watch streamed-response benchmarks after changing chunk sizes or websocket write behavior.
- Compare sequential and parallel tunnel results before raising concurrency caps; if parallel performance flattens early, the bottleneck is usually websocket serialization or the local upstream, not route lookup.

## Suggested Workflow

1. Run `make bench` on the main branch and save the output.
2. Re-run after transport, buffering, or timeout changes.
3. If a benchmark regresses materially, run `go test -bench ... -cpuprofile cpu.out -memprofile mem.out` on the affected package before changing limits.
