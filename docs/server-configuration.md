# Server Configuration

Complete reference for all server flags, environment variables, and defaults.

## Starting the Server

Interactive setup (recommended for first time):

```bash
expose server init
```

The init wizard asks for each parameter, writes a `.env` file, and optionally creates your first API key. Use `expose server init --env-file /path/to/server.env` to choose a different output path.

The wizard accepts `dynamic` and `wildcard` TLS modes and defaults to `dynamic`. The normal `expose server` runtime also accepts `auto`, and defaults to `auto` when `EXPOSE_TLS_MODE` is unset.

Manual start:

```bash
export EXPOSE_DOMAIN=example.com
expose server
```

## Environment Variables & Flags

Every setting can be provided as a CLI flag or environment variable. Environment variables take effect when the corresponding flag is not explicitly passed.

| Flag                      | Env Variable                     | Default       | Description                                                    |
| ------------------------- | -------------------------------- | ------------- | -------------------------------------------------------------- |
| `--domain`                | `EXPOSE_DOMAIN`                  | _(required)_  | Public base domain (e.g. `example.com`)                        |
| `--listen`                | `EXPOSE_LISTEN_HTTPS`            | `:10443`      | HTTPS listen address                                           |
| `--http-challenge-listen` | `EXPOSE_LISTEN_HTTP_CHALLENGE`   | `:10080`      | ACME HTTP-01 challenge listener                                |
| `--pprof-listen`          | `EXPOSE_PPROF_LISTEN`            | -             | Optional pprof listen address (loopback only unless `EXPOSE_PPROF_ALLOW_REMOTE=true`) |
| -                         | `EXPOSE_PPROF_ALLOW_REMOTE`      | `false`       | Allow an unauthenticated pprof listener on a non-loopback address |
| `--db`                    | `EXPOSE_DB_PATH`                 | `./expose.db` | SQLite database path                                           |
| `--publish-dir`           | `EXPOSE_PUBLISH_DIR`             | `<db path>.sites` | Storage directory for published static sites                 |
| `--publish-max-bytes`     | `EXPOSE_PUBLISH_MAX_BYTES`       | `10485760` | Maximum total extracted size per published site, in bytes, default 10 MiB |
| `--db-max-open-conns`     | `EXPOSE_DB_MAX_OPEN_CONNS`       | `10`          | SQLite max open connections                                    |
| `--db-max-idle-conns`     | `EXPOSE_DB_MAX_IDLE_CONNS`       | `10`          | SQLite max idle connections                                    |
| `--tls-mode`              | `EXPOSE_TLS_MODE`                | `auto`        | TLS mode: `auto`, `dynamic`, or `wildcard`                     |
| `--cert-cache-dir`        | `EXPOSE_CERT_CACHE_DIR`          | `./cert`      | ACME certificate cache directory                               |
| `--tls-cert-file`         | `EXPOSE_TLS_CERT_FILE`           | -             | Static PEM certificate (for wildcard/auto)                     |
| `--tls-key-file`          | `EXPOSE_TLS_KEY_FILE`            | -             | Static PEM private key (for wildcard/auto)                     |
| `--api-key-pepper`        | `EXPOSE_API_KEY_PEPPER`          | random, persisted | Explicit pepper for API key hashing                         |
| `--access-cookie-secret`  | `EXPOSE_ACCESS_COOKIE_SECRET`    | random, persisted | Secret used to sign protected-route access cookies          |
| `--log-level`             | `EXPOSE_LOG_LEVEL`               | `info`        | Log verbosity: `debug`, `info`, `warn`, `error`                |
| -                         | `EXPOSE_WAF_ENABLE`              | `true`        | Enable/disable the Web Application Firewall                    |
| -                         | `EXPOSE_WAF_AUDIT_ONLY`          | `false`       | Evaluate WAF rules without blocking requests                   |
| -                         | `EXPOSE_WAF_BODY_INSPECT_LIMIT`  | `16384`       | Max public request-body bytes the WAF inspects (`0` disables)  |
| -                         | `EXPOSE_WAF_MAX_URI_LENGTH`      | `8192`        | Maximum request URI length before the WAF blocks it             |
| -                         | `EXPOSE_WAF_MAX_HEADER_COUNT`    | `64`          | Maximum non-exempt header-value count before the WAF blocks it  |
| -                         | `EXPOSE_MAX_PENDING_PER_TUNNEL`  | `128`         | Max in-flight public HTTP requests per active tunnel           |
| -                         | `EXPOSE_PUBLIC_RATE_LIMIT_RPS`   | `0`           | Optional public request rate limit per hostname+client IP      |
| -                         | `EXPOSE_PUBLIC_RATE_LIMIT_BURST` | `0`           | Burst for the public request limit (`0` auto-derives from RPS) |
| -                         | `EXPOSE_ACME_ISSUE_RATE_PER_HOUR` | `10`         | Max new ACME issuances per hour (`0` disables this limiter)    |
| -                         | `EXPOSE_TRUSTED_PROXY_CIDRS`     | -             | Comma-separated proxy CIDRs trusted when resolving client IP   |
| -                         | `EXPOSE_ROUTE_CACHE_TTL`         | `1m`          | Positive hostname route cache TTL before DB revalidation       |
| -                         | `EXPOSE_WAF_COUNTER_RETENTION`   | `1h`          | Retention window for in-memory per-host WAF counters           |
| -                         | `EXPOSE_AUTOUPDATE`              | `false`       | Enable automatic self-update (`true`/`1`/`yes`)                |
| -                         | `EXPOSE_REQUIRE_SIGNATURE`       | `false`       | Require cosign verification for self-updates                   |

## HTTP/3 + QUIC Behavior

- The server always starts HTTP/3 on the same listen address as HTTPS (`EXPOSE_LISTEN_HTTPS`).
- There is no separate QUIC listen or advertise setting in current versions.
- For clients using QUIC (`--transport=quic`), your public TCP and UDP paths must use the same authority/port.
- If UDP is unavailable, clients connect over WebSocket (the default transport).

## `.env` File Support

The server loads `.env` from the working directory on startup. Variables already present in the environment are not overwritten.

Example `.env`:

```bash
EXPOSE_DOMAIN=example.com
EXPOSE_PPROF_LISTEN=127.0.0.1:6060
EXPOSE_TLS_MODE=auto
EXPOSE_DB_PATH=./expose.db
EXPOSE_CERT_CACHE_DIR=./cert
EXPOSE_API_KEY_PEPPER=your-secret-pepper
EXPOSE_ACCESS_COOKIE_SECRET=your-access-cookie-secret
EXPOSE_LOG_LEVEL=info
EXPOSE_WAF_ENABLE=true
EXPOSE_WAF_AUDIT_ONLY=false
EXPOSE_WAF_BODY_INSPECT_LIMIT=16384
EXPOSE_WAF_MAX_URI_LENGTH=8192
EXPOSE_WAF_MAX_HEADER_COUNT=64
EXPOSE_PUBLIC_RATE_LIMIT_RPS=0
EXPOSE_PUBLIC_RATE_LIMIT_BURST=0
EXPOSE_ACME_ISSUE_RATE_PER_HOUR=10
EXPOSE_TRUSTED_PROXY_CIDRS=
EXPOSE_AUTOUPDATE=true
```

## DNS Requirements

Before clients can connect, create DNS records for your domain:

| Record   | Type | Name | Value              |
| -------- | ---- | ---- | ------------------ |
| Apex     | A    | `@`  | Server public IPv4 |
| Wildcard | A    | `*`  | Server public IPv4 |

- `@` covers the base domain (`example.com`)
- `*` covers all subdomains (`*.example.com`)
- ACME modes (`auto`/`dynamic`) require ports 80 and 443 reachable from the internet

Provider-specific guides: [Cloudflare](dns-cloudflare.md) · [GoDaddy](dns-godaddy.md) · [Namecheap](dns-namecheap.md)

## Port Forwarding

The server listens on non-privileged ports by default. If you're behind NAT or a router, forward:

| Public Port         | Internal Port       | Purpose                             |
| ------------------- | ------------------- | ----------------------------------- |
| 443                 | 10443               | HTTPS tunnel traffic                |
| same as HTTPS (UDP) | same as HTTPS (UDP) | HTTP/3 QUIC tunnel traffic (always) |
| 80                  | 10080               | ACME HTTP-01 challenges             |

See [Port Forwarding](port-forwarding.md) for router-specific instructions.
For NAT and load-balancer layouts, see [UDP Deployment Topologies](udp-deployment-topologies.md).

To listen on standard ports directly (requires capabilities or root):

```bash
export EXPOSE_LISTEN_HTTPS=:443
export EXPOSE_LISTEN_HTTP_CHALLENGE=:80
```

## TLS Modes

| Mode       | How it works                            | Best for                             |
| ---------- | --------------------------------------- | ------------------------------------ |
| `auto`     | Static wildcard cert + ACME fallback    | General use                          |
| `dynamic`  | Per-host ACME HTTP-01 only (ignores cert files) | Simple setups, low tunnel churn |
| `wildcard` | Static wildcard cert, no ACME           | Many short-lived tunnels, air-gapped |

See [TLS Modes](tls-modes.md) for the full comparison and decision guide.

## API Key Pepper

API keys are hashed with SHA-256 plus a pepper for additional security. If no pepper is configured, the server generates a random value on first use and persists it in SQLite. A configured pepper must match the persisted value. See [API Keys - Pepper](api-keys.md#pepper) for details.

Back up the SQLite database to retain the generated pepper. If you configure `EXPOSE_API_KEY_PEPPER` explicitly, keep it stable and synchronized with that database.

## Access Cookie Secret

Protected routes in `form` mode issue a signed edge-session cookie after a successful login. That cookie is now signed with `EXPOSE_ACCESS_COOKIE_SECRET`, not with the stored password hash.

- If omitted, the server generates a cryptographically random secret on first use, persists it in SQLite, and reuses it after restarts.
- Set `EXPOSE_ACCESS_COOKIE_SECRET` when you want to manage the secret explicitly instead.
- The generated secret is ephemeral only if the database cannot be read or written; in that failure case, form-login sessions are invalidated on restart.

## Health Check

The server exposes `GET /healthz` which returns `200 OK`. This endpoint is exempt from WAF inspection and is useful for load balancer or uptime monitoring probes.

## Debug Profiling

Enable Go `pprof` endpoints for live diagnosis:

```bash
EXPOSE_PPROF_LISTEN=127.0.0.1:6060 expose server
```

This exposes the standard profiles under `/debug/pprof/`. For example:

```bash
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

The server also publishes Prometheus text metrics at `/debug/metrics` on the
same listener. Neither endpoint has application authentication, so keep this
listener on loopback or restrict it at the network boundary.

## Rate Limiting

The server applies token-bucket rate limiting to tunnel registration requests (`/v1/tunnels/register`). Limits are per API key:

- **5 registrations/second** sustained rate
- **10 burst** capacity

Clients that exceed the limit receive `429 Too Many Requests`.

You can also enable an optional public traffic limit with:

- `EXPOSE_PUBLIC_RATE_LIMIT_RPS`
- `EXPOSE_PUBLIC_RATE_LIMIT_BURST`

That limiter is applied per `hostname + client IP` before the request reaches tunnel auth or proxying. Set burst to `0` to derive it automatically as `2 x RPS`.

## Active Tunnel Limit

Each API key has a configurable tunnel limit that controls how many active tunnels it can have simultaneously. New keys default to **50** active tunnels.

### Setting during key creation

```bash
expose apikey create --name mykey --tunnel-limit 10
```

### Updating an existing key

```bash
expose apikey set-limit --id <key-id> --tunnel-limit 5
```

Use `--tunnel-limit -1` to remove the limit (unlimited).

When a key with an active limit reaches its maximum concurrent tunnels, the server responds with `429 Too Many Requests` and error code `tunnel_limit`.

## Background Maintenance

The server runs a background janitor that automatically:

- Expires stale WebSocket sessions
- Cleans up temporary tunnel domains after a retention period
- Purges old entries from the ACME certificate cache

## See Also

- [Quick Start](quick-start.md) - up and running in 5 minutes
- [VPS Deployment](vps-deployment.md) - systemd service, firewall, and production setup
- [Architecture Overview](architecture-overview.md) - how the server works internally
