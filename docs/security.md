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
- Brute-force API key guessing (bcrypt hashing, constant-time comparison)
- Scanner and bot probes (User-Agent blocklist, sensitive file path rules)

### What is out of scope

- Application-level authentication and authorization in local services
- Protection against attacks that don't traverse the tunnel (e.g., LAN-side attacks)
- DDoS mitigation beyond basic rate limiting (use an upstream CDN/firewall for volumetric attacks)

## Authentication

### API Keys

API keys authenticate tunnel registration requests. Keys are hashed before storage:

- **Hashing**: bcrypt with `DefaultCost` (currently 10 rounds)
- **Pepper**: An optional server-wide pepper (`EXPOSE_API_KEY_PEPPER`) is prepended before hashing. If not configured, one is auto-generated at startup
- **Comparison**: Hex hash strings are compared using `crypto/subtle.ConstantTimeCompare` to prevent timing attacks
- **Storage**: Only bcrypt hashes are stored in SQLite; raw keys are never persisted

### Tunnel Connect Tokens

After successful registration the server issues a short-lived connect token. The client presents this token when establishing the WebSocket or HTTP/3 tunnel connection. Tokens are single-use and expire quickly.

### Password-Protected Tunnels

Tunnels can require a password for public access. When enabled:

- Visitors see a login form served by the server
- Passwords are verified against a bcrypt hash stored with the tunnel
- On success, the server sets a signed cookie so repeat visits don't re-prompt
- Form output is HTML-escaped with `html.EscapeString` to prevent XSS

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

If `EXPOSE_ACCESS_COOKIE_SECRET` is not configured, an ephemeral secret is generated at startup. This means protected-route sessions reset on server restart. Configure a persistent secret for production use.

## Transport Encryption

### HTTPS (WebSocket Transport)

- TLS 1.2 minimum for HTTPS connections
- Supports static certificates or dynamic per-host ACME (Let's Encrypt)
- Wildcard mode uses a pre-provisioned wildcard certificate
- Dynamic mode provisions individual certificates on demand via ACME HTTP-01 or DNS-01 challenges

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
- **Sensitive field exclusion**: Password-like form/JSON fields are excluded from pattern scanning to reduce false positives
- **Body inspection limits**: Only the first N bytes (configurable via `EXPOSE_WAF_BODY_INSPECT_LIMIT`) are scanned; binary and multipart bodies are skipped
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

The server injects and **overwrites** standard reverse-proxy headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port`) to prevent client-side spoofing. Pre-existing values from the incoming request are replaced.

## Recommendations for Operators

1. **Set `EXPOSE_ACCESS_COOKIE_SECRET`** to a persistent random value in production to survive restarts
2. **Set `EXPOSE_API_KEY_PEPPER`** and keep it stable — changing it invalidates all existing API keys
3. **Use wildcard TLS mode** with a pre-provisioned certificate for production deployments to avoid ACME rate limits
4. **Enable WAF** (on by default) and start with audit mode if concerned about false positives
5. **Deploy behind a CDN or L4 firewall** for volumetric DDoS protection, which is outside expose's scope
6. **Rotate API keys periodically** and revoke unused keys via the admin API
