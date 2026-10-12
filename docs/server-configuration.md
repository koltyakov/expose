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
| `--bypasses`              | `EXPOSE_BYPASSES`                | `[]`          | JSON array of server-only subdomain routes to local HTTP ports |
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

## Server-local services

Use bypass routes to expose services running on the same server without a tunnel client. Each route reserves a subdomain and proxies requests directly to an HTTP service on `127.0.0.1` at the configured port.

Add this to the server's `.env`:

```bash
EXPOSE_BYPASSES='[{"subdomain":"app","port":3000},{"subdomain":"ci","port":8080,"disable_waf":true}]'
```

With `EXPOSE_DOMAIN=example.com`, `https://app.example.com` reaches `127.0.0.1:3000`, and `https://ci.example.com` reaches `127.0.0.1:8080`. Bind those services to loopback so callers cannot reach them directly and skip expose's protections.

You can also pass the JSON array through `expose server --bypasses='[...]'`. A flag replaces the environment value; `--bypasses='[]'` disables all configured bypass routes. Restart the server to apply changes.

| Field | Default | Description |
| --- | --- | --- |
| `subdomain` | required | Subdomain relative to `EXPOSE_DOMAIN`, using the same naming rules as tunnels |
| `port` | required | Local HTTP service port, from 1 to 65535 |
| `disable_waf` | `false` | Skip WAF inspection for this route's application requests |
| `disable_rate_limit` | `false` | Skip the configured public request rate limit for this route |

"Bypass" means bypassing the tunnel transport, not bypassing security. Routes inherit the server's WAF settings and public rate limits unless explicitly opted out. WAF is enabled by default; public rate limiting still requires `EXPOSE_PUBLIC_RATE_LIMIT_RPS`. TLS termination, trusted client-IP resolution, forwarding-header sanitization, request deadlines, and the per-route in-flight limit remain active. `EXPOSE_MAX_PENDING_PER_TUNNEL` also limits concurrent requests and WebSocket connections per bypass route.

HTTP bodies stream without a total-size cap, and WebSocket upgrades are supported. The public hostname, path, query, application credentials, and application cookies reach the service. Expose's access cookie does not. The `/_expose/v1` service namespace and health endpoint keep their existing behavior, including WAF inspection of service API requests even on a route with `disable_waf`.

Bypasses and their security opt-outs are server-only. Clients cannot create, change, or claim them. `expose http`, `expose static`, and `expose pub` receive the usual hostname-in-use conflict for a reserved name, even when the local service is offline. Unknown configuration fields and duplicate subdomains cause a startup error.

A configured bypass takes precedence over an existing client tunnel or publication at the same hostname. Existing client records remain intact, but the tunnel cannot resume or reconnect and the publication cannot be replaced while its name is reserved. Removing the bypass releases the server-side reservation on restart.

WebRTC signaling services can use a bypass for their HTTP and WebSocket endpoints without disabling WAF. SDP and ICE candidates travel over the application WebSocket; WebRTC packets flow directly between peers or through a public TURN relay. TURN/STUN listeners and relay allocation traffic need separately reachable network ports, not HTTP bypass routes. See [TURN relay](turn-relay.md) for external ICE URLs and temporary credentials.

## HTTP/3 + QUIC Behavior

For the separate optional WebRTC TURN service, see [TURN relay](turn-relay.md). TURN listeners and relay allocation ports must be reachable independently of the HTTP tunnel.

Tunneled HTTP uploads and downloads have no total-body size limit. Large bodies stream through bounded buffers on both WebSocket and HTTP/3 transports, including chunked requests without `Content-Length`. The upstream application can enforce its own upload limit. WAF inspection remains bounded by `EXPOSE_WAF_BODY_INSPECT_LIMIT`; registration and static-site publishing keep their separate request and extracted-size limits. `EXPOSE_PUBLISH_MAX_BYTES` applies only to server-hosted static sites, not tunneled uploads.

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

The server exposes `GET /_expose/healthz` which returns `200 OK`. This endpoint is exempt from WAF inspection and is useful for load balancer or uptime monitoring probes.

### Service API namespace and upgrades

Expose reserves `/_expose/v1` and its descendants for tunnel registration, WebSocket and HTTP/3 connections, and publication management. Health probes use `/_expose/healthz`. Published-site presence continues to use `/_expose/presence` and `/_expose/presence.js`.

Application paths such as `/v1/*` and `/healthz` reach the tunnel or published site and receive normal WAF inspection. There are no legacy service aliases on these paths.

When upgrading from a version using `/v1/*`, upgrade the server and all tunnel and publishing clients together. Older clients cannot register or manage publications against the new API. Update health probes and any reverse-proxy path rules to the new namespace. Stored keys, hostnames, and published files need no migration.

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

The server applies token-bucket rate limiting to tunnel registration requests (`/_expose/v1/tunnels/register`). Limits are per API key:

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
