# Client Configuration

Complete reference for all client flags, environment variables, and credential management.

## Commands

| Command                             | Description                                       |
| ----------------------------------- | ------------------------------------------------- |
| `expose http <port>`                | Expose a local port (temporary subdomain)         |
| `expose http <port> --domain=myapp` | Expose with a named subdomain                     |
| `expose http <port> --protect`      | Expose with password protection                   |
| `expose static [dir]`               | Expose a static directory                         |
| `expose soak --port 3000`           | Run many temporary clients against one local port |
| `expose auth curl --url <url>`       | Authenticate curl against an access-form route    |
| `expose login`                      | Save server URL and API key                       |
| `expose list`                       | List your tunnels and published sites            |
| `expose up`                         | Start routes from `expose.yml`                    |
| `expose up init`                    | Create `expose.yml` via wizard                    |
| `expose update`                     | Update to the latest release                      |

## List tunnels and published sites

```bash
expose list
expose list --json
expose list --retention=336h  # Include the last 14 days
expose list --retention=0     # Include all retained entries
expose list --server=https://example.com --api-key=KEY
```

`expose client list` is an alias. The command uses your saved login, environment variables, or explicit credential flags. Results are scoped to your API key on the selected server, including tunnels started from other machines.

By default, the list hides inactive entries last seen more than 7 days ago. `--retention` accepts a Go duration such as `24h` or `336h`; `0` disables the filter. Connected tunnels always appear. Published sites always appear until they expire, regardless of last seen; sites without an expiry always appear. This retention setting controls listing visibility, not deletion or hostname release.

Tunnel activity includes registration, connections, disconnections, and public requests. Published-site activity includes publishing, republishing, public requests, and presence heartbeats. Activity survives server restarts; older entries without recorded activity fall back to their creation time. Public-request activity is recorded asynchronously, so the last-seen time may take a moment to update.

The table shows subdomain (`NAME`), type, status, last activity (`SEEN`), and publication expiry. `SEEN` shows time since the last recorded activity, such as `now`, `5m ago`, `2h ago`, or `3d ago`; `-` means unavailable. It includes tunnels created by `http`, `static`, and `up`, plus sites uploaded with `pub`. Each hostname appears once, sorted by hostname. A connected tunnel takes precedence over older sessions; otherwise the latest registration is shown. An `up` configuration with multiple paths under one hostname occupies one row.

Terminal output uses one row per hostname, with short type labels (`named`, `temp`, `site`), green online indicators, and dim offline entries. Names omit the selected server's base domain and port, preserving nested subdomains such as `docs.api`. The name column is capped at 28 characters, including `...` for longer names, and shrinks further to fit narrow terminals. Below 72 columns, the expiry column is omitted while `SEEN` stays visible. Expiry times use local time. Set `NO_COLOR=1` to disable color; redirected output uses the same compact table in plain text. Use `--json` for full hostnames, URLs, and timestamps.

JSON tunnel statuses are `connected`, `disconnected`, or `closed`; published site statuses are `active` or `expired`. The table labels connected tunnels and active sites as `online`, and disconnected tunnels as `offline`. Disconnected and closed hostnames appear within the retention window while the server retains their reservations. Temporary hostnames and expired sites disappear after cleanup. Listing does not renew reservations or publication TTLs.

`--json` returns an array with `id`, `type` (`tunnel` or `site`), `hostname`, `url`, `status`, `created_at`, and `last_active_at`. Temporary tunnels also include `temporary: true`; sites with an expiry include `expires_at`. The same retention filter applies to JSON. An empty list returns `[]`.

Both client and server must support this command. If an older server returns 404, the client asks you to update it. The API is `GET /_expose/v1/exposures`, authenticated with your API key in the `Authorization: Bearer KEY` header.

The API also defaults to seven days and accepts a `retention` query parameter, for example `GET /_expose/v1/exposures?retention=336h` or `?retention=0` for all retained entries.

## Shared Tunnel Flags & Environment Variables

| Flag             | Env Variable                     | Description                                                                          |
| ---------------- | -------------------------------- | ------------------------------------------------------------------------------------ |
| `--domain`       | `EXPOSE_SUBDOMAIN`               | Requested subdomain label (e.g. `myapp`)                                             |
| `--server`       | `EXPOSE_DOMAIN`                  | Server URL (e.g. `example.com`)                                                      |
| `--api-key`      | `EXPOSE_API_KEY`                 | API key for authentication                                                           |
| `--transport`    | `EXPOSE_TRANSPORT`               | Tunnel transport: `ws` (default), `quic`                                             |
| `--protect`      | -                                | Enable protection for this tunnel (`form` by default, `basic` via `--protect=basic`) |
| -                | `EXPOSE_USER`                    | Access-form username (default: `admin`)                                              |
| -                | `EXPOSE_PASSWORD`                | Access-form password                                                                 |
| -                | `EXPOSE_CLIENT_MACHINE_ID`       | Stable client machine ID override used for registration and default static hostnames |
| -                | `EXPOSE_WAF_IGNORE_PATHS`        | Comma-separated path prefixes ignored by the WAF sensitive-file rule                 |
| -                | `EXPOSE_MAX_CONCURRENT_FORWARDS` | Max concurrent local upstream forwards per client process (default: `128`)           |
| -                | `EXPOSE_PPROF_LISTEN`            | Optional pprof address (loopback only unless `EXPOSE_PPROF_ALLOW_REMOTE=true`)        |
| -                | `EXPOSE_PPROF_ALLOW_REMOTE`      | Allow an unauthenticated pprof listener on a non-loopback address                     |
| -                | `EXPOSE_AUTOUPDATE`              | Enable automatic self-update for `http` and `static` (`true`/`1`/`yes`)              |
| -                | `EXPOSE_REQUIRE_SIGNATURE`       | Require cosign verification for self-updates (`true`/`1`/`yes`)                      |

## Command-Specific Flags

| Command            | Useful flags                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| `http`             | `--port` (or positional port / `EXPOSE_PORT`)                                                                 |
| `static`           | `--dir`, `--folders`, `--spa`, and repeatable `--allow <glob>`; `--allow` is static-only                      |
| `up`, `up init`    | `-f` / `--file` to select the config path; `up init` requires an interactive terminal                        |
| `auth curl`        | `--url`, `--user`, `--password`, `--insecure`, and `--format curl\|header\|cookie`                           |
| `soak`             | `--port`, `--count`, `--duration`, `--ramp`, `--report-interval`, `--churn-interval`, `--churn-batch`, `--prefix`, `--pprof-listen` |

## Per-Tunnel WAF Paths

Set `EXPOSE_WAF_IGNORE_PATHS` when an application intentionally serves URL
subtrees containing dot-prefixed path segments:

Single path for one command:

```bash
EXPOSE_WAF_IGNORE_PATHS=/generated/assets expose http 3000
```

Multiple paths are comma-separated:

```bash
EXPOSE_WAF_IGNORE_PATHS=/generated/assets,/runtime/cache,/node_modules/.cache expose http 3000
```

Export the value for subsequent client commands:

```bash
export EXPOSE_WAF_IGNORE_PATHS="/generated/assets,/runtime/cache"
expose http 3000
```

Or define it in the project's `.env` file, which client commands load
automatically:

```dotenv
EXPOSE_WAF_IGNORE_PATHS=/generated/assets,/runtime/cache
```

Each location matches the exact URL path and all descendants. For example,
`/generated/assets` matches both `/generated/assets` and
`/generated/assets/client/app.js`, but not `/generated/assets-old/app.js`.
Paths must be absolute, may not contain `.` or `..` segments, and are limited
to 16 entries per tunnel.

This exception applies only to the WAF's **Sensitive File Probe** rule. SQL
injection, XSS, path traversal, and every other WAF rule remain active. The rule
is registered with this tunnel and does not affect other clients or subdomains.

## Credential Resolution

The client resolves server URL and API key from multiple sources, with this priority:

1. **CLI flags** (`--server`, `--api-key`) - highest priority
2. **Environment variables** (`EXPOSE_DOMAIN`, `EXPOSE_API_KEY`)
3. **`.env` file** in the current directory
4. **Saved credentials** from `expose login` (`~/.expose/settings.json`) - lowest priority

This means you can `expose login` once and never pass credentials again, or override per-command with flags or env vars.

## Transport Selection (`--transport`)

| Value  | Behavior                                                                                          |
| ------ | ------------------------------------------------------------------------------------------------- |
| `ws`   | WebSocket (default). Highest throughput and lowest latency in the common case.                    |
| `quic` | Uses HTTP/3 only (multi-stream preferred, then compatibility mode), never falls back to WebSocket |

Notes:

- `--transport` applies to `expose http` and `expose static`.
- WebSocket is the default because it delivers higher throughput and lower latency in the common case (see [Benchmark Report](benchmark.md)). Use `--transport=quic` when you need QUIC benefits: lossy or high-latency networks, mobile/roaming clients, or environments where middleboxes break long-lived WebSocket connections.
- HTTP/3 requires UDP reachability on the same public port as HTTPS.

## Login

Save credentials locally so you don't need `--server` and `--api-key` on every command:

```bash
expose login --server example.com --api-key <KEY>
```

In an interactive terminal, if `--server` or `--api-key` is omitted, the CLI prompts for missing values.

Credentials are stored in:

| OS            | Path                                  |
| ------------- | ------------------------------------- |
| macOS / Linux | `~/.expose/settings.json`             |
| Windows       | `%USERPROFILE%\.expose\settings.json` |

File permissions are set to `0600` (owner-only read/write).

## Tunnel Types

### Temporary (default)

When `--domain` is not set, the server allocates a short random hostname:

```bash
expose http 3000
# → https://k3xnz3.example.com
```

Temporary tunnels are cleaned up after disconnect. See [Temporary Host Allocation](temporary-host-allocation.md) for how slugs are generated.

### Named

Request a stable subdomain that persists across reconnects:

```bash
expose http 3000 --domain=myapp
# → https://myapp.example.com
```

Flags before the port are also supported:

```bash
expose http --domain=myapp 3000
```

The requested name is always relative to the server's configured base domain;
it is not an arbitrary custom hostname. Multi-label names such as `foo.bar`
become `foo.bar.example.com` and may require a certificate broader than the
usual `*.example.com` wildcard.

## Password Protection

Add protection in front of your tunnel:

```bash
# Interactive - default form-based protection
expose http 3000 --domain=myapp --protect

# Non-interactive - password from env
EXPOSE_USER=admin EXPOSE_PASSWORD=secret expose http 3000 --domain=myapp

# Legacy compatibility - explicit Basic Auth
expose http 3000 --domain=myapp --protect=basic
```

> **Note**: `--protect` defaults to the edge access form and avoids consuming your app's `Authorization` header. Use `--protect=basic` only when you explicitly want legacy Basic Auth behavior.

For CLI testing, use:

```bash
expose auth curl --url https://myapp.example.com --password "$EXPOSE_PASSWORD"
```

Add `--format header` to print a `Cookie:` header you can pass directly to `curl -H`.

## Static Files

Use `expose static` for local folders, docs sites, and SPAs:

```bash
expose static

# or choose a directory explicitly
expose static ./public
```

Static mode reuses the same client auth flow as `expose http`, including `--server`, `--api-key`, and `--protect`.

See [Static Sites](static-sites.md) for the full static-mode reference, including:

- `--folders`, `--spa`, and `--allow`
- default hostname behavior
- security defaults for hidden files and public file types
- Markdown rendering and Mermaid support
- examples for SPAs, docs, and downloads

## Multi-Route Config (`expose up`)

For projects with multiple services, use `expose.yml`:

```bash
expose up init    # guided wizard
expose up         # start all routes
expose up -f ./custom.yml
```

See [expose up](expose-up.md) for the full config reference.

## Client Dashboard

The client shows a real-time terminal UI with:

- Connection status and uptime
- Public URL and local target
- Request log with method, path, status, and duration
- Latency percentiles (P50/P90/P95/P99)
- Active clients and WebSocket connection count
- Combined inbound and outbound traffic totals with live 1-second rates
- WAF blocked count (when WAF is enabled on server)
- Update availability notifications

See [Client Dashboard](client-dashboard.md) for details.

## Keyboard Shortcuts

| Key      | Action                |
| -------- | --------------------- |
| `Ctrl+C` | Quit                  |
| `Ctrl+I` | Toggle session details |
| `Ctrl+U` | Trigger manual update |

## Auto-Update

For `expose http` and `expose static`, `EXPOSE_AUTOUPDATE=true` checks for updates on startup and periodically (every 30 minutes). Updates are downloaded and applied automatically, then the process restarts.

See [Auto-Update](auto-update.md) for configuration details.

## Reconnection

The client automatically reconnects when the connection drops:

- Staged retry delays of 2 seconds, 5 seconds, then 15 seconds
- Periodic keepalive pings maintain the connection
- Server version changes trigger an update check (when auto-update is enabled)

## Debug Profiling

Enable Go `pprof` endpoints for a client process when diagnosing live overloads or memory growth:

```bash
EXPOSE_PPROF_LISTEN=127.0.0.1:6060 expose http 3000
```

The client exposes the standard endpoints under `/debug/pprof/`, for example:

```bash
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

`expose up` also honors `EXPOSE_PPROF_LISTEN`, but the listener is process-level, not per route.

## Soak Testing

Use `expose soak` to measure connected tunnel ceilings and reconnect behavior with many client sessions in one process:

```bash
expose soak --port 3000 --count 200 --duration 10m
```

To add churn:

```bash
expose soak --port 3000 --count 200 --duration 10m --churn-interval 30s --churn-batch 10
```

The soak runner creates unique temporary named tunnels, prints rolling active/peak/error counters, and exits non-zero if no tunnel ever becomes ready.

## See Also

- [Quick Start](quick-start.md) - get started in 5 minutes
- [API Keys](api-keys.md) - create and manage keys
- [Local Testing](local-testing.md) - single-machine E2E with `127.0.0.1.sslip.io`
