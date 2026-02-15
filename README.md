# expose

`expose` is a simple BYOI (bring your own infrastructure) tunneling tool, similar to ngrok.

It has two modes:
- `client` mode (default): expose a local HTTP service.
- `server` mode: authenticate clients, terminate TLS, route public traffic, and manage tunnel state in SQLite.

## Features

- API key auth
- Temporary tunnels with auto-generated subdomains
- Permanent tunnels with reserved hostnames
- Automatic SSL via Let's Encrypt (ACME HTTP-01)
- Optional static wildcard TLS certs (DNS-01) with dynamic ACME fallback
- Single binary CLI

## Install

```bash
go build -o bin/expose ./cmd/expose
```

Or run without building:

```bash
go run ./cmd/expose --help
```

## Quick Start

### 1. Start server

Set required env vars:

```bash
export EXPOSE_BASE_DOMAIN=example.com
export EXPOSE_API_KEY_PEPPER=change-me
export EXPOSE_DB_PATH=./expose.db
```

Run server:

```bash
go run ./cmd/expose server --base-domain "$EXPOSE_BASE_DOMAIN" --api-key-pepper "$EXPOSE_API_KEY_PEPPER" --db "$EXPOSE_DB_PATH"
```

For local/dev without TLS:

```bash
go run ./cmd/expose server --base-domain "$EXPOSE_BASE_DOMAIN" --api-key-pepper "$EXPOSE_API_KEY_PEPPER" --db "$EXPOSE_DB_PATH" --insecure-http --http-challenge-listen :8080
```

### 2. Create API key

```bash
go run ./cmd/expose server apikey create --db "$EXPOSE_DB_PATH" --api-key-pepper "$EXPOSE_API_KEY_PEPPER" --name default
```

Save the printed `api_key`.

### 3. Expose local service (client mode)

```bash
go run ./cmd/expose --server https://tunnel.example.com --api-key <api_key> --local http://127.0.0.1:3000
```

Because client is default mode, `expose client ...` is optional.

## CLI

```text
expose [client-flags]
expose client [flags]
expose server [flags]
expose server apikey create [flags]
expose server apikey list [flags]
expose server apikey revoke [flags]
```

### Client flags

- `--server` server URL, for example `https://tunnel.example.com` (required)
- `--api-key` API key (required)
- `--local` local upstream URL, default `http://127.0.0.1:3000`
- `--subdomain` requested subdomain
- `--permanent` reserve hostname across reconnects
- If `--subdomain` is empty and server runs without wildcard TLS, server attempts a stable short hash subdomain from client machine name + local port.

### Server flags

- `--base-domain` base domain, for example `example.com` (required)
- `--db` SQLite path, default `./expose.db`
- `--api-key-pepper` key hashing pepper (required)
- `--listen` HTTPS listen address, default `:443`
- `--http-challenge-listen` HTTP challenge listen address, default `:80`
- `--public-url` public server URL used for WS connect URLs
- `--tls-mode` TLS strategy: `auto|dynamic|wildcard` (default `auto`)
- `--cert-cache-dir` cert cache dir, default `./cert-cache`
- `--tls-cert-file` static TLS certificate PEM file (optional)
- `--tls-key-file` static TLS key PEM file (optional)
- `--log-level` `debug|info|warn|error`
- `--insecure-http` disable ACME/TLS and run plain HTTP

### Wildcard TLS (Let's Encrypt DNS-01)

Use this when you want one cert for `example.com` + `*.example.com` instead of per-host cert issuance.

1. Set `EXPOSE_TLS_MODE=wildcard`.
2. Create a DNS API token in your DNS provider with permission to edit TXT records for your zone.
3. Use Certbot with your DNS provider plugin to issue:
   - `example.com`
   - `*.example.com`
4. Point `EXPOSE_TLS_CERT_FILE` to `fullchain.pem` and `EXPOSE_TLS_KEY_FILE` to `privkey.pem` (or copy them to `EXPOSE_CERT_CACHE_DIR/wildcard.crt` and `EXPOSE_CERT_CACHE_DIR/wildcard.key`).
5. Restart server.

Example Certbot shape (replace `<provider>` with your plugin):

```bash
certbot certonly --agree-tos --email you@example.com --non-interactive \
  --dns-<provider> --dns-<provider>-credentials <credentials-file> \
  -d example.com -d '*.example.com'
```

## Make targets

```bash
make help
make tidy
make fmt
make test
make build
```

## Notes

- v1 supports HTTP/HTTPS tunneling only.
- Server is single-node and stores state in SQLite.
- Permanent tunnels return `503` while offline.
- Temporary tunnels are released when client disconnects.
- Client heartbeat timeout is based on last inbound tunnel message (ping or response), reducing false disconnects.
- Inactive temporary domains and their certificate cache entries are removed by retention-based cleanup.
- Client receives the effective server TLS mode in register response (`dynamic` or `wildcard`) and logs it.
- TLS modes:
  - `auto`: use wildcard cert if available, else dynamic per-host ACME fallback.
  - `dynamic`: force dynamic per-host ACME only.
  - `wildcard`: force wildcard mode; if certs are missing, startup prints DNS-01/API walkthrough and exits.
