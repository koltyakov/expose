# Security Model

This document describes the security architecture of **expose** — how authentication, encryption, and attack mitigation work together to protect tunneled traffic.

## Threat Model

expose acts as a reverse proxy: public HTTPS traffic arrives at the server, travels through a tunnel transport to the client, and is forwarded to a local application. The security boundary exists at two layers:

1. **Server ↔ Internet** — TLS termination, WAF inspection, rate limiting
2. **Server ↔ Client** — authenticated tunnel with encrypted transport

### What expose protects against

- Unauthenticated tunnel registration (API key required)
- Common web attacks reaching local apps (WAF blocks SQLi, XSS, path traversal, etc.)
- Eavesdropping on tunnel traffic (TLS 1.2+ / QUIC encryption)
- Session hijacking on protected tunnels (HMAC-signed cookies)
- Brute-force API key guessing (peppered SHA-256 hashing, constant-time comparison)
- Scanner and bot probes (User-Agent blocklist, sensitive file path rules)

### What is out of scope

- Application-level authentication and authorization in local services
- Protection against attacks that don't traverse the tunnel (e.g., LAN-side attacks)
- DDoS mitigation beyond basic rate limiting (use an upstream CDN/firewall for volumetric attacks)

## Authentication

### API Keys

API keys authenticate tunnel registration requests. Keys are hashed before storage:

- **Hashing**: SHA-256 over `key + ":" + pepper`, hex-encoded. A fast hash is appropriate here because API keys are 256-bit cryptographically random values — brute-forcing a 2^256 key space is computationally infeasible, so the slow-hash defense needed for low-entropy human passwords (which do use bcrypt, see below) adds no value
- **Pepper**: A server-wide pepper is appended before hashing. If `EXPOSE_API_KEY_PEPPER` is not configured, a cryptographically random pepper is generated on first use and persisted in SQLite. If configured, it must match any persisted pepper
- **Comparison**: Hex hash strings are compared using `crypto/subtle.ConstantTimeCompare` to prevent timing attacks
- **Storage**: Only SHA-256 digests are stored in SQLite; raw keys are never persisted

### Tunnel Connect Tokens

After successful registration the server issues a short-lived connect token. The client presents this token when establishing the WebSocket or HTTP/3 tunnel connection. Tokens are single-use and expire quickly.

### Password-Protected Tunnels

Tunnels can require a password for public access. When enabled:

- Visitors see a login form served by the server
- Passwords are verified against a bcrypt hash stored with the tunnel
- On success, the server sets a signed cookie so repeat visits don't re-prompt
- Form output is rendered through `html/template`, whose contextual autoescaping prevents XSS

## Cookie Security

Access cookies for password-protected tunnels use:

| Property | Value |
|----------|-------|
| **Signature** | HMAC-SHA256 with a server-configured secret (`EXPOSE_ACCESS_COOKIE_SECRET`) |
| **TTL** | 24 hours |
| **HttpOnly** | Yes |
| **Secure** | Yes |
| **SameSite** | Lax |
| **Scope** | Signature includes the tunnel's password hash, preventing lateral use across tunnels |

If `EXPOSE_ACCESS_COOKIE_SECRET` is not configured, a cryptographically random secret is generated on first use and persisted in SQLite, so protected-route sessions survive normal restarts. The server uses an ephemeral random secret only when the database cannot be read or written; sessions then reset on restart.

## Transport Encryption

### HTTPS (WebSocket Transport)

- TLS 1.2 minimum for HTTPS connections
- Supports static certificates or dynamic per-host ACME (Let's Encrypt)
- Wildcard mode uses a pre-provisioned wildcard certificate
- Dynamic mode provisions individual certificates on demand via ACME HTTP-01 challenges

### HTTP/3 (QUIC Transport)

- TLS 1.3 enforced (required by QUIC specification)
- Same certificate infrastructure as HTTPS
- Two modes: `h3_compat` (single stream) and `h3_multistream` (dedicated streams per request)

### SNI Validation

The server validates the SNI hostname in TLS ClientHello against registered tunnel domains, rejecting connections for unknown hosts before certificate provisioning.

## Web Application Firewall (WAF)

The built-in WAF inspects every proxied request before it reaches the tunnel. See the [dedicated WAF documentation](waf.md) for the full ruleset.

Key design decisions:

- **Defense in depth**: The WAF is a supplementary layer, not a replacement for application-level validation
- **Double-decode detection**: Query strings are decoded twice to catch `%25XX`-style encoding evasion
- **Sensitive field privacy**: Password-like form/JSON fields are inspected like any other input, but request-body values are not written to WAF logs. Logs include the complete request URI, including its query string, so do not place secrets in query parameters. Excluding password-like fields from scanning was previously used to reduce false positives, but it was trivially bypassed by naming an attack parameter `password`. The trade-off is that a password containing rule-matching text (`' OR 1=1`, `<script`) can now cause the login request to be blocked
- **Body inspection limits**: Only the first N bytes (configurable via `EXPOSE_WAF_BODY_INSPECT_LIMIT`, default 16 KiB) are scanned. Form keys and values are normalized and inspected. JSON object keys plus string and numeric values are inspected, with encoded variants of string values normalized. Multipart bodies are parsed and each field name, filename, form value, and UTF-8 file content is scanned. UTF-8 `application/octet-stream` payloads are also scanned; non-text binary content is skipped. Use `EXPOSE_WAF_IGNORE_PATHS` on the client to bypass the Sensitive File Probe rule for selected path prefixes; all other WAF rules still apply
- **Audit mode**: `EXPOSE_WAF_AUDIT_ONLY=true` logs matches without blocking, for safe rollout

## Rate Limiting

- Tunnel registration is rate-limited (5 requests/second with burst allowance)
- Rate limiter uses 16 shards with FNV hashing to minimize lock contention
- Idle rate limiter entries are cleaned up after 5 minutes to prevent unbounded memory growth

## Data Storage

- **SQLite with WAL mode**: Enables concurrent reads while maintaining write serialization
- **Parameterized queries throughout**: No string concatenation for SQL construction
- **Transaction timeouts**: 30-second default to prevent deadlocks
- **Domain allocation**: Protected by database unique constraints to prevent race conditions

## Random Number Generation

All security-sensitive random values (API key generation, token creation, ephemeral secrets) use `crypto/rand`, never `math/rand`.

## Forwarded Headers

The server injects standard reverse-proxy headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port`). For `X-Forwarded-For`, all incoming header values are preserved, normalized into one canonical chain, and the immediate peer's IP is appended as the rightmost hop. This lets an upstream trusted proxy's chain pass through while still recording who connected to expose.

**Trust rule**: only the LAST hop of `X-Forwarded-For` (the immediate peer) is inherently trustworthy; every earlier hop is client-controllable unless it was added by a proxy you trust. When expose sits behind a known reverse proxy or CDN, set `EXPOSE_TRUSTED_PROXY_CIDRS` to a comma-separated list of trusted proxy CIDRs (e.g. `10.0.0.0/8,203.0.113.10/32`). When the immediate peer matches a trusted CIDR, the client IP is derived from the rightmost XFF hop that is NOT in a trusted CIDR. The default is empty, which means no XFF hop is trusted and the client IP is always the connection's `RemoteAddr`.

## Release Integrity

Release artifacts are signed with [cosign](https://docs.sigstore.dev/) in **keyless mode**: the release workflow authenticates to Sigstore via GitHub Actions OIDC (`id-token: write`), so there are no long-lived signing keys to manage or leak. GoReleaser signs `checksums.txt`, producing one Sigstore bundle:

- `checksums.txt.sigstore.json` - the signature, certificate, and verification material for `checksums.txt`

Since `checksums.txt` carries the SHA-256 digest of every archive, verifying its signature authenticates all release artifacts at once.

### Verifying a release manually

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp "^https://github\.com/koltyakov/expose/\.github/workflows/release\.yml@refs/tags/.*$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

The certificate identity pins the signature to this repository's release workflow running from a version tag; the OIDC issuer pins it to GitHub Actions.

### How each install path verifies

- **`scripts/install.sh`**: verifies `checksums.txt` with cosign when cosign is available on the system. If signature assets cannot be downloaded while cosign is installed, installation fails closed rather than silently downgrading. If cosign itself is absent, the script warns and falls back to checksum-only verification; the checksum manifest then comes from the same origin as the archive (trust on first use).
- **Built-in self-update** (`expose update`): relies on GitHub TLS plus the SHA-256 checksum manifest, and additionally refuses non-HTTPS download URLs and asset hosts outside the GitHub allowlist. In-binary signature verification is intentionally omitted: pulling in the sigstore libraries would add heavy dependencies to the binary, and full signature verification is available via the install script or the manual command above.

## Recommendations for Operators

1. **Back up SQLite server settings** so automatically generated API-key and access-cookie secrets survive restores
2. **Keep `EXPOSE_API_KEY_PEPPER` stable if configured** - it must match the value persisted in SQLite
3. **Use wildcard TLS mode** with a pre-provisioned certificate for production deployments to avoid ACME rate limits
4. **Enable WAF** (on by default) and start with audit mode if concerned about false positives
5. **Deploy behind a CDN or L4 firewall** for volumetric DDoS protection, which is outside expose's scope
6. **Rotate API keys periodically** and revoke unused keys with `expose apikey revoke`
