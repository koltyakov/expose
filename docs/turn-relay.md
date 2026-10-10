# TURN relay

Expose can run a TURN relay on its public server for WebRTC applications whose peers cannot connect directly. The relay supports UDP allocations over UDP, TCP and TLS connections. It forwards packets without decrypting WebRTC's DTLS traffic.

This is a separate public network service, not UDP forwarding through `expose http`. Existing HTTP tunnels and clients need no protocol changes. Switching an HTTP tunnel to QUIC does not enable WebRTC relaying.

## Enable on the public server

Add these settings to the server's `.env`:

```dotenv
EXPOSE_TURN_ENABLE=true
EXPOSE_TURN_PUBLIC_IP=203.0.113.10
EXPOSE_TURN_SECRET=replace-with-output-of-openssl-rand-hex-32
EXPOSE_TURN_LISTEN_UDP=:3478
EXPOSE_TURN_LISTEN_TCP=:3478
EXPOSE_TURN_LISTEN_TLS=:5349
EXPOSE_TURN_MIN_PORT=49160
EXPOSE_TURN_MAX_PORT=49200
```

Replace the example IP with the server's public IPv4. Generate a secret with `openssl rand -hex 32`, then restart `expose server`. Missing or invalid relay settings stop startup rather than silently disabling TURN. The service is off by default.

TCP/TLS lets a phone reach TURN when its network blocks UDP. Peer-facing relay allocations are still UDP, so the public server must have UDP connectivity.

TLS is optional and uses Expose's existing HTTPS certificate provider. The public TURN hostname defaults to `EXPOSE_DOMAIN`. A custom `EXPOSE_TURN_HOST` is authorized for ACME when the TURN TLS listener is enabled. Its DNS must point directly to the server, and the normal ACME challenge ports must be reachable. Static certificates must cover the TURN hostname.

## Open the network ports

| Port | Protocol | Purpose |
| --- | --- | --- |
| 3478 | UDP | TURN over UDP |
| 3478 | TCP | TURN over TCP |
| 5349 | TCP | TURN over TLS, if enabled |
| 49160-49200 | UDP | Peer-facing relay allocations |

Open these ports in the host firewall and cloud firewall. Behind NAT, forward listener and allocation ports without changing their numbers. `EXPOSE_TURN_PUBLIC_IP` must be the external IPv4, while `EXPOSE_TURN_RELAY_ADDRESS` selects the local interface for allocations.

TURN-over-TLS is not HTTPS. It cannot pass through an HTTP reverse proxy, CDN proxy, or Expose HTTP tunnel. A network allowing only TCP 443 needs a dedicated public IP or a TCP-level router to reach a TURN TLS listener on 443. Expose does not multiplex HTTPS and TURN on one TCP listener. Do not assign TURN's UDP listener to the HTTP/3 listener's address either.

## Obtain temporary credentials

A trusted application backend can request credentials using an Expose API key:

```bash
curl --request POST \
  --header "Authorization: Bearer $EXPOSE_API_KEY" \
  https://example.com/_expose/v1/turn/credentials
```

The response has this shape:

```json
{
  "iceServers": [{
    "urls": [
      "turn:example.com:3478?transport=udp",
      "turn:example.com:3478?transport=tcp",
      "turns:example.com:5349?transport=tcp"
    ],
    "username": "<expiry-unix-seconds>:<api-key-id>",
    "credential": "<temporary-password>"
  }],
  "expiresAt": 1800000000
}
```

Only enabled listeners appear in `urls`. The response is not cacheable. Issuance uses the existing per-IP authentication limit and shares the registration limit of 5 requests/second per API key with burst 10. A disabled relay returns `503`; missing, invalid or revoked keys return `401`.

Pass `iceServers` to both WebRTC peers, then obtain fresh credentials before they expire. For browser clients:

```js
const pc = new RTCPeerConnection({ iceServers: credentials.iceServers });
```

Keep the Expose API key and TURN shared secret on trusted backends. Send only the temporary credentials to devices, through the application's authenticated signaling channel. This endpoint does not automatically configure tunneled applications.

Alternatively, a trusted signaling server can generate standard TURN REST credentials using the shared secret:

- Username is `<expiry-unix-seconds>:<user-id>`.
- Password is Base64 of HMAC-SHA1 of that username, keyed by `EXPOSE_TURN_SECRET`.
- Expiry must be in the future, no more than 24 hours ahead.

For Varro App, its signaling server needs external TURN configuration or a credential-provider integration to distribute these URLs and credentials. Enabling this Expose service alone does not update Varro's current ICE list.

## Configuration reference

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--turn` | `EXPOSE_TURN_ENABLE` | `false` | Enable relay |
| `--turn-public-ip` | `EXPOSE_TURN_PUBLIC_IP` | required when enabled | Advertised IPv4 |
| `--turn-host` | `EXPOSE_TURN_HOST` | base domain | Hostname in ICE URLs |
| none | `EXPOSE_TURN_SECRET` | required when enabled | Shared secret, at least 32 characters |
| `--turn-realm` | `EXPOSE_TURN_REALM` | base domain | Authentication realm |
| `--turn-listen-udp` | `EXPOSE_TURN_LISTEN_UDP` | `:3478` | UDP listener; `off` disables |
| `--turn-listen-tcp` | `EXPOSE_TURN_LISTEN_TCP` | `:3478` | TCP listener; `off` disables |
| `--turn-listen-tls` | `EXPOSE_TURN_LISTEN_TLS` | disabled | TLS listener; `off` disables |
| `--turn-relay-address` | `EXPOSE_TURN_RELAY_ADDRESS` | `0.0.0.0` | Local IPv4 for allocation sockets |
| `--turn-min-port` | `EXPOSE_TURN_MIN_PORT` | `49160` | First allocation port |
| `--turn-max-port` | `EXPOSE_TURN_MAX_PORT` | `49200` | Last allocation port, inclusive |
| `--turn-max-allocations` | `EXPOSE_TURN_MAX_ALLOCATIONS` | `128` | Global allocation cap across listeners |
| `--turn-max-connections` | `EXPOSE_TURN_MAX_CONNECTIONS` | `128` | Global TCP/TLS connection cap, including unauthenticated clients |
| `--turn-credential-ttl` | `EXPOSE_TURN_CREDENTIAL_TTL` | `1h` | Issued credential lifetime, between `1m` and `24h` |

The port range also bounds allocations, so the smaller of available ports and the allocation cap determines capacity. This implementation supports IPv4 peers only, not TCP relay allocations or IPv6 allocations.

## Security and shutdown

The relay rejects permissions for loopback, private, link-local, multicast, shared-address, reserved and documentation networks. This blocks access to LAN services and cloud metadata addresses through TURN. Peer traffic does not pass through the HTTP WAF. Restrict the relay further with network egress rules where needed.

Unauthenticated TCP/TLS clients have 10 seconds to authenticate. Authenticated connections have a 10-minute read-idle timeout, and writes have a 15-second timeout. Allocation and connection limits bound concurrent sockets, but there is no per-user bandwidth quota. Monitor and limit bandwidth at the host or network boundary.

Revoking an API key stops new credential issuance. Already-issued credentials remain usable until expiry; rotating the TURN secret invalidates their authentication. Existing allocations can carry traffic until their allocation lifetime expires or the server closes. Server shutdown closes listeners, accepted connections and allocation sockets, including idle unauthenticated clients.
