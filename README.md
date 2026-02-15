# expose

`expose` is a simple BYOI (bring your own infrastructure) tunneling tool, similar to ngrok.

It has two modes:
- `client` mode (default): expose a local HTTP service.
- `server` mode: authenticate clients, terminate TLS, route public traffic, and manage tunnel state in SQLite.

## Features

- API key auth
- Temporary tunnels with auto-generated subdomains
- Permanent tunnels with reserved hostnames
- Bring your own custom domain
- Automatic SSL via Let's Encrypt (ACME HTTP-01)
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
- `--domain` custom domain
- `--permanent` reserve hostname across reconnects

### Server flags

- `--base-domain` base domain, for example `example.com` (required)
- `--db` SQLite path, default `./expose.db`
- `--api-key-pepper` key hashing pepper (required)
- `--listen` HTTPS listen address, default `:443`
- `--http-challenge-listen` HTTP challenge listen address, default `:80`
- `--public-url` public server URL used for WS connect URLs
- `--cert-cache-dir` cert cache dir, default `./cert-cache`
- `--log-level` `debug|info|warn|error`
- `--insecure-http` disable ACME/TLS and run plain HTTP

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
