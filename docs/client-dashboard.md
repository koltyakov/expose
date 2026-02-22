# Client Dashboard

The expose client displays a real-time terminal UI that shows tunnel status, request traffic, and performance metrics.

## Overview

When you run `expose http` or `expose up`, the client renders a live dashboard:

```
expose v1.0.0                                        (Ctrl+C to quit)

Session     online for 2h 15m (ID: abc123)
Server      v1.0.0 (WAF: On, TLS: Auto)
Update      v1.1.0 available — run expose update or press Ctrl+U
Latency     12ms
Forwarding  https://myapp.example.com → http://127.0.0.1:3000 (healthy)
Clients     2 active, 5 total
WebSockets  1 open

HTTP Requests    42 total, blocked 3
──────────────────────────────────────────────────────────────
14:23:01  GET     /api/users                         200    12ms
14:23:02  POST    /api/users                         201     8ms
14:22:58  GET     /static/app.js                     304     2ms
14:22:55  WARN    WAF blocked request: SQL injection

Latency         P50 8ms | P90 15ms | P95 22ms | P99 45ms
```

## Dashboard Fields

| Field        | Description                                                                 |
| ------------ | --------------------------------------------------------------------------- |
| **Session**  | Connection status (`online`/`connecting`), uptime, and tunnel ID            |
| **Server**   | Server version with WAF and TLS mode indicators                              |
| **Update**   | Shown when a newer version is available                                      |
| **Latency**  | Current round-trip latency to the server (from keepalive pings)             |
| **Forwarding** | Public URL → local target, with health status of local port                |
| **Clients**  | Active and total unique visitor count                                        |
| **WebSockets** | Number of open WebSocket relay connections                                 |

## Request Log

Each proxied request is displayed with:

- **Timestamp** — when the request was received
- **Method** — HTTP method (`GET`, `POST`, etc.)
- **Path** — request path (truncated to 40 chars if needed)
- **Status** — HTTP status code (color-coded: green for 2xx, yellow for 3xx/4xx, red for 5xx)
- **Duration** — round-trip time for the request

Special entries:

- **WARN** — WAF-blocked requests or connection warnings
- **INFO** — Informational messages (reconnections, updates)

## Latency Percentiles

After enough requests are collected, the dashboard shows latency distribution:

```
Latency         P50 8ms | P90 15ms | P95 22ms | P99 45ms
```

These are calculated from recent request round-trip times.

## WAF Indicators

When the server has WAF enabled:

- The Server line shows **WAF: On**
- The HTTP Requests summary shows a **blocked** counter
- WAF-blocked requests appear as **WARN** entries in the request log
- Block counts update in real time via keepalive pong messages

## Local Port Health

The Forwarding line shows the health status of your local target:

- **healthy** — local port is responding
- Status is checked automatically

## Keyboard Shortcuts

| Key       | Action                              |
| --------- | ----------------------------------- |
| `Ctrl+C`  | Quit the client gracefully          |
| `Ctrl+U`  | Trigger immediate update check      |

## Color Output

The dashboard uses ANSI colors for readability:

- **Cyan** — public URL, info messages
- **Green** — 2xx status codes, online status
- **Yellow** — 3xx/4xx status codes, warnings, connecting status
- **Red** — 5xx status codes, blocked requests
- **Dim** — timestamps, separators, secondary info

## See Also

- [Client Configuration](client-configuration.md) — all client flags and env vars
- [Auto-Update](auto-update.md) — update notifications and Ctrl+U
- [Web Application Firewall](waf.md) — WAF rules and blocked request details
