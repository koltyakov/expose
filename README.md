# expose

`expose` is a BYOI tunnel: run your own server, then expose local HTTP ports from clients.

## What Changed

- Server and client are env-first. `make run-server` / `make run-client` no longer bind many CLI flags.
- Client exposes a local `port` (not a local URL).
- Client supports `login` and stores credentials in temp settings:
  - `<temp>/.expose/settings.json`
  - Windows: `%TEMP%\.expose\settings.json`
  - Linux/macOS: usually `/tmp/.expose/settings.json`
- External public traffic is HTTPS-only.
- Single domain parameter: `EXPOSE_DOMAIN` (for example `example.com`).

## Defaults

- HTTPS listen: `:10443`
- ACME HTTP-01 challenge listen: `:10080`
- SQLite DB: `./expose.db`
- Cert cache: `./cert`

If you run behind Docker, NAT, or a router, forward:
- `443 -> 10443` (TCP)
- `80 -> 10080` (TCP)

## DNS Setup (`@` and `*` A records)

Create DNS records for your `EXPOSE_DOMAIN` zone before starting clients:

- `A` record `@` -> your server public IPv4
- `A` record `*` -> your server public IPv4

Optional for IPv6:

- `AAAA` record `@` -> your server public IPv6
- `AAAA` record `*` -> your server public IPv6

Notes:

- `@` covers the apex domain (`example.com`).
- `*` covers dynamic subdomains (`<anything>.example.com`).
- Dynamic ACME (`EXPOSE_TLS_MODE=auto|dynamic`) needs public reachability on ports `80` and `443`.

## Quick Start

### 1. Configure server env

```bash
export EXPOSE_DOMAIN=example.com
export EXPOSE_TLS_MODE=auto
```

Optional:

```bash
export EXPOSE_DB_PATH=./expose.db
export EXPOSE_CERT_CACHE_DIR=./cert
export EXPOSE_API_KEY_PEPPER=...
```

If `EXPOSE_API_KEY_PEPPER` is unset and no machine-id is available, server initializes with an empty pepper.

### 2. Start server

```bash
go run ./cmd/expose server
```

Or:

```bash
make run-server
```

### 3. Create API key

```bash
go run ./cmd/expose server apikey create --name default
```

Copy `api_key` from output.

### 4. Login client once

```bash
go run ./cmd/expose login --server https://example.com --api-key <api_key>
```

If `--server` or `--api-key` is omitted in an interactive shell, `expose login` prompts for missing values.
In CI/non-interactive runs, pass both flags to avoid prompts.

Or:

```bash
make client-login
```

### 5. Expose local app port

```bash
go run ./cmd/expose http 3000
```

Or:

```bash
export EXPOSE_PORT=3000
make run-client
```

`--server` and `--api-key` are optional after login (stored settings are used). You can still pass them to override.

Named tunnel example:

```bash
go run ./cmd/expose http --domain=my-app 8080
```

This requests `https://my-app.<EXPOSE_DOMAIN>`.

## CLI

```text
expose [tunnel-flags]
expose login [flags]
expose http [flags] <port>
expose tunnel [flags]
expose client [flags]
expose client login [flags]
expose client http [flags] <port>
expose client tunnel [flags]
expose server [flags]
expose server apikey create [flags]
expose server apikey list [flags]
expose server apikey revoke [flags]
```

### Client flags

- `http` command:
  - `expose http 3000` -> temporary/random subdomain
  - `expose http --domain=myapp 3000` -> `https://myapp.<EXPOSE_DOMAIN>`
  - optional overrides: `--server`, `--api-key`
- `--port` local HTTP port on `127.0.0.1` (required outside `expose http <port>` form)
- `--server` server URL (HTTPS)
- `--api-key` API key
- `--name` requested tunnel name (subdomain)
- `--permanent` reserve tunnel/domain permanently (legacy; `--name` already enables this)

Default mode is temporary. If `--name` is not set, host allocation is automatic:

- Wildcard TLS active: randomized temporary host (6-char slug) is allocated.
- Wildcard TLS not active: server first tries a deterministic host from `client_hostname + ":" + local_port`:
  - `sha1(client_hostname:local_port)` -> base32 lowercase -> first 6 chars
  - example shape: `k3xnz3.example.com`
  - on collision, server falls back to randomized 6-char host

Why randomization exists:

- avoids users accidentally claiming memorable names in temporary mode
- reduces hostname collisions across clients
- keeps temporary endpoints disposable

### Server flags

- `--domain` public base domain (required if `EXPOSE_DOMAIN` is not set)
- `--listen` HTTPS listen address (default `:10443`)
- `--http-challenge-listen` ACME challenge listen (default `:10080`)
- `--db` SQLite DB path (default `./expose.db`)
- `--tls-mode` `auto|dynamic|wildcard` (default `auto`)
- `--cert-cache-dir` cert cache dir (default `./cert`)
- `--tls-cert-file` static cert file (wildcard mode)
- `--tls-key-file` static key file (wildcard mode)
- `--api-key-pepper` explicit pepper override (optional)

## Wildcard TLS Mode

Use `EXPOSE_TLS_MODE=wildcard` to serve `example.com` and `*.example.com` from one static wildcard cert.

When to use wildcard mode:

- you expect many short-lived temporary subdomains
- you want to avoid frequent per-host certificate issuance
- you want predictable TLS behavior across many rotating hosts

If wildcard cert files are missing, server prints a concrete Let's Encrypt DNS-01 walkthrough and exits:
- required SANs
- expected file locations
- certbot command shape

Dynamic per-host ACME is available in `auto` / `dynamic` and is best for simpler setups with low tunnel churn.

## Internal Reliability Behavior

- Client sends keepalive pings automatically.
- Client reconnects with backoff if server/session drops.
- Server expires stale sessions and closes stale temporary tunnels.
- Stale temporary domains and old temporary cert cache files are purged automatically.
- Server persists a single effective API-key pepper in DB (`server_settings`) so restarts/container moves do not break existing keys.
