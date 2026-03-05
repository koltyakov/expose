# UDP Deployment Topologies

Operator guidance for HTTP/3 tunnel traffic when your network path is not the default "single host, open 443/tcp + 443/udp" setup.

## Core Rule

`expose server` always serves HTTPS and HTTP/3 on the same listen authority (`EXPOSE_LISTEN_HTTPS`).

- TCP must reach that port for HTTPS.
- UDP must also reach that same port for QUIC / HTTP/3.

If UDP is blocked, clients still work through WebSocket fallback (`--transport=auto`) but lose HTTP/3 benefits.

## Topology 1: Direct Edge Host

Use when the server has a public IP.

- Open inbound `443/tcp` and `443/udp` (or your custom HTTPS port for both protocols).
- Keep DNS `A` / wildcard records pointed directly at that host.

## Topology 2: Home NAT / Port Forwarding

Use when the server is behind a router.

- Forward `443/tcp -> <server>:10443/tcp` (or your chosen internal HTTPS port).
- Forward `443/udp -> <server>:10443/udp`.
- Keep both forwards symmetric; mismatched UDP forwarding is a common HTTP/3 failure source.

## Topology 3: L4 Load Balancer

Use when multiple backends are behind a TCP/UDP pass-through balancer.

- Frontend listeners must include both TCP and UDP on the same public port.
- Preserve pass-through semantics (no TLS termination if you want end-to-end tunnel authority consistency).
- Use connection-stable routing (source-hash / 5-tuple hash) so QUIC packets stay pinned to one backend.

## Topology 4: Reverse Proxy in Front

Most HTTP reverse proxies handle TCP well but do not proxy HTTP/3 tunnel streams correctly.

- Prefer L4 pass-through for tunnel traffic.
- If QUIC pass-through is unavailable, expect HTTP/3 to fail and WebSocket fallback to be used.

## Unsupported Layout: Different Public UDP Port

Current `expose` versions do not support advertising a different public UDP port for QUIC than the HTTPS authority.

- Example unsupported edge mapping: `443/tcp` + `8443/udp`.
- Use the same public port for both TCP and UDP if you need QUIC.
- If you cannot do that, run clients with `--transport=auto` (or `--transport=ws`) and rely on WebSocket transport.

## Validation Checklist

1. Confirm TCP path:
   - `curl -I https://<your-domain>/healthz`
2. Confirm UDP path:
   - `nc -vzu <your-domain> 443` (or your HTTPS public port)
3. Confirm advertise/connect behavior:
   - Run client with `--transport=quic` and verify it does not fall back.
4. Confirm fallback behavior:
   - Run client with `--transport=auto` and verify it reconnects via `ws` when UDP is blocked.
