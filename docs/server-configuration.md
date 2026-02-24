# Server Configuration

Complete reference for all server flags, environment variables, and defaults.

## Starting the Server

Interactive setup (recommended for first time):

```bash
expose server init
```

The init wizard asks for each parameter, writes a `.env` file, and optionally creates your first API key.

Manual start:

```bash
export EXPOSE_DOMAIN=example.com
expose server
```

## Environment Variables & Flags

Every setting can be provided as a CLI flag or environment variable. Environment variables take effect when the corresponding flag is not explicitly passed.

| Flag                      | Env Variable                   | Default       | Description                                   |
| ------------------------- | ------------------------------ | ------------- | --------------------------------------------- |
| `--domain`                | `EXPOSE_DOMAIN`                | _(required)_  | Public base domain (e.g. `example.com`)        |
| `--listen`                | `EXPOSE_LISTEN_HTTPS`          | `:10443`      | HTTPS listen address                           |
| `--http-challenge-listen` | `EXPOSE_LISTEN_HTTP_CHALLENGE` | `:10080`      | ACME HTTP-01 challenge listener                |
| `--db`                    | `EXPOSE_DB_PATH`               | `./expose.db` | SQLite database path                           |
| `--tls-mode`              | `EXPOSE_TLS_MODE`              | `auto`        | TLS mode: `auto`, `dynamic`, or `wildcard`     |
| `--cert-cache-dir`        | `EXPOSE_CERT_CACHE_DIR`        | `./cert`      | ACME certificate cache directory               |
| `--tls-cert-file`         | `EXPOSE_TLS_CERT_FILE`         | -             | Static PEM certificate (for wildcard/auto)     |
| `--tls-key-file`          | `EXPOSE_TLS_KEY_FILE`          | -             | Static PEM private key (for wildcard/auto)     |
| `--api-key-pepper`        | `EXPOSE_API_KEY_PEPPER`        | -             | Explicit pepper for API key hashing            |
| `--log-level`             | `EXPOSE_LOG_LEVEL`             | `info`        | Log verbosity: `debug`, `info`, `warn`, `error`|
| -                         | `EXPOSE_WAF_ENABLE`            | `true`        | Enable/disable the Web Application Firewall    |
| -                         | `EXPOSE_AUTOUPDATE`            | `false`       | Enable automatic self-update (`true`/`1`/`yes`)|

## `.env` File Support

The server loads `.env` from the working directory on startup. Variables already present in the environment are not overwritten.

Example `.env`:

```bash
EXPOSE_DOMAIN=example.com
EXPOSE_TLS_MODE=auto
EXPOSE_DB_PATH=./expose.db
EXPOSE_CERT_CACHE_DIR=./cert
EXPOSE_API_KEY_PEPPER=your-secret-pepper
EXPOSE_LOG_LEVEL=info
EXPOSE_WAF_ENABLE=true
EXPOSE_AUTOUPDATE=true
```

## DNS Requirements

Before clients can connect, create DNS records for your domain:

| Record | Type | Name | Value              |
| ------ | ---- | ---- | ------------------ |
| Apex   | A    | `@`  | Server public IPv4 |
| Wildcard | A  | `*`  | Server public IPv4 |

- `@` covers the base domain (`example.com`)
- `*` covers all subdomains (`*.example.com`)
- ACME modes (`auto`/`dynamic`) require ports 80 and 443 reachable from the internet

Provider-specific guides: [Cloudflare](dns-cloudflare.md) · [GoDaddy](dns-godaddy.md) · [Namecheap](dns-namecheap.md)

## Port Forwarding

The server listens on non-privileged ports by default. If you're behind NAT or a router, forward:

| Public Port | Internal Port | Purpose                    |
| ----------- | ------------- | -------------------------- |
| 443         | 10443         | HTTPS tunnel traffic       |
| 80          | 10080         | ACME HTTP-01 challenges    |

See [Port Forwarding](port-forwarding.md) for router-specific instructions.

To listen on standard ports directly (requires capabilities or root):

```bash
export EXPOSE_LISTEN_HTTPS=:443
export EXPOSE_LISTEN_HTTP_CHALLENGE=:80
```

## TLS Modes

| Mode       | How it works                            | Best for                             |
| ---------- | --------------------------------------- | ------------------------------------ |
| `auto`     | Static wildcard cert + ACME fallback    | General use                          |
| `dynamic`  | Per-host ACME only (ignores cert files) | Simple setups, low tunnel churn      |
| `wildcard` | Static wildcard cert, no ACME           | Many short-lived tunnels, air-gapped |

See [TLS Modes](tls-modes.md) for the full comparison and decision guide.

## API Key Pepper

API keys are hashed with SHA-256 plus a pepper for additional security. See [API Keys - Pepper](api-keys.md#pepper) for details on pepper derivation, persistence, and migration.

**Production recommendation**: always set `EXPOSE_API_KEY_PEPPER` explicitly.

## Health Check

The server exposes `GET /healthz` which returns `200 OK`. This endpoint is exempt from WAF inspection and is useful for load balancer or uptime monitoring probes.

## Rate Limiting

The server applies token-bucket rate limiting to tunnel registration requests (`/v1/tunnels/register`). Limits are per API key:

- **5 registrations/second** sustained rate
- **10 burst** capacity

Clients that exceed the limit receive `429 Too Many Requests`.

## Active Tunnel Limit

Each API key has a configurable tunnel limit that controls how many active tunnels it can have simultaneously. The default is **unlimited** (`-1`).

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
- Persists the effective API key pepper in the database (`server_settings` table)

## See Also

- [Quick Start](quick-start.md) - up and running in 5 minutes
- [VPS Deployment](vps-deployment.md) - systemd service, firewall, and production setup
- [Architecture Overview](architecture-overview.md) - how the server works internally
