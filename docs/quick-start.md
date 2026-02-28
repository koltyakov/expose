# Quick Start

Get a local HTTP service publicly accessible in under 5 minutes.

## Prerequisites

- Go 1.23+ (to build from source)
- A domain you control (e.g. `example.com`)
- A server with a public IP (VPS, home server, etc.)

## Build

```bash
go build -o bin/expose ./cmd/expose
```

## 1 - Start the server

On your public-facing machine:

```bash
./bin/expose server init
```

Or configure environment variables manually:

```bash
export EXPOSE_DOMAIN=example.com
export EXPOSE_TLS_MODE=auto
./bin/expose server
```

> Ports `10443` (HTTPS) and `10080` (ACME HTTP-01) must be reachable from the internet. See [Port Forwarding](port-forwarding.md) if you're behind a router.

## 2 - Create an API key

On the same server:

```bash
./bin/expose apikey create --name my-key
```

Copy the `api_key` value from the output.

## 3 - Login from a client machine

```bash
./bin/expose login --server example.com --api-key <YOUR_API_KEY>
```

Credentials are saved to `~/.expose/settings.json` - you only need to do this once.

## 4 - Expose a local port

Start your local app (e.g. on port 3000), then:

```bash
./bin/expose http 3000
./bin/expose static
```

You'll see output like:

```
tunnel ready  public_url=https://k3xnz3.example.com  tunnel_id=...
```

Open the URL in your browser - traffic is tunnelled to `127.0.0.1:3000`.

> Security notice: if your server is using per-host ACME certificates
> (`dynamic`, or `auto` without a matching wildcard certificate), new public
> hostnames are often discovered and probed by bots shortly after they are
> created. Protect new tunnels immediately and use `--protect` for anything
> non-public. For static-mode details, see [Static Sites](static-sites.md).

## Named subdomain

Request a stable subdomain:

```bash
./bin/expose http --domain=myapp 3000
```

This gives you `https://myapp.example.com` every time.

## What's next?

| Topic                | Guide                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------- |
| Server configuration | [Server Configuration](server-configuration.md)                                             |
| Client configuration | [Client Configuration](client-configuration.md)                                             |
| DNS records setup    | [GoDaddy](dns-godaddy.md) · [Cloudflare](dns-cloudflare.md) · [Namecheap](dns-namecheap.md) |
| Router / NAT setup   | [Port Forwarding](port-forwarding.md)                                                       |
| Cloud deployment     | [VPS Deployment](vps-deployment.md)                                                         |
| Multi-route config   | [expose up](expose-up.md)                                                                   |
| TLS options          | [TLS Modes](tls-modes.md)                                                                   |
| Key management       | [API Keys](api-keys.md)                                                                     |
| Auto-update          | [Auto-Update](auto-update.md)                                                               |
| Client terminal UI   | [Client Dashboard](client-dashboard.md)                                                     |
| Local machine E2E    | [Local Testing](local-testing.md)                                                           |
