# Client Dashboard

The expose client displays a real-time terminal UI that shows tunnel status, request traffic, and performance metrics.

## Overview

When you run `expose http` or `expose static`, the client renders a live dashboard:

```
expose v1.0.0                                        (Ctrl+C to quit)

Session     online for 2h 15m (ID: abc123)
            99.8% uptime, 1 disconnect
Server      v1.0.0 (WAF: On, TLS: Auto)
Update      v1.1.0 available - run expose update or press Ctrl+U
Latency     12ms
Forwarding  https://myapp.example.com → http://127.0.0.1:3000 (healthy)
Notice      tunnel register failed, connect: connection refused; retrying in 2s
Traffic     In 1.5 MB total (180 KB/s) | Out 980 KB total (96 KB/s)
Clients     2 active, 5 total
WebSockets  1 open

HTTP Requests    42 total, blocked 3
──────────────────────────────────────────────────────────────
14:23:01  GET     /api/users                         200    12ms
14:23:02  POST    /api/users                         201     8ms
14:22:58  GET     /static/app.js                     304     2ms

Latency         P50 8ms | P90 15ms | P95 22ms | P99 45ms
```

## Dashboard Fields

| Field          | Description                                                                   |
| -------------- | ----------------------------------------------------------------------------- |
| **Session**    | Connection status (`online`/`connecting`), uptime, and tunnel ID              |
| **Details**    | Optional session uptime percentage and disconnect count, toggled with `Ctrl+I` |
| **Server**     | Server version with WAF and TLS mode indicators                               |
| **Update**     | Shown when a newer version is available                                       |
| **Latency**    | Current round-trip latency to the server (from keepalive pings)               |
| **Forwarding** | Public URL → local target, with health status of local port                   |
| **Notice**     | Most recent client-side warning/info message (retries, provisioning, updates) |
| **Clients**    | Active and total unique visitor count                                         |
| **Traffic**    | Combined inbound/downloaded and outbound/uploaded totals with live 1-second rolling rates |
| **WebSockets** | Number of open WebSocket relay connections                                    |

Traffic includes proxied HTTP request/response bodies and WebSocket frame
payloads. It does not include headers, TLS overhead, tunnel framing, or other
control messages.

## Request Log

Each proxied request is displayed with:

- **Timestamp** - when the request was received
- **Method** - HTTP method (`GET`, `POST`, etc.)
- **Path** - request path (truncated to 40 chars if needed)
- **Status** - HTTP status code (color-coded: green for 2xx, yellow for 3xx/4xx, red for 5xx)
- **Duration** - round-trip time for the request

Only forwarded HTTP requests appear in this section. Client-side warnings and
info messages are shown in the **Notice** field instead of being mixed into the
request log.

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
- Block counts update in real time via keepalive pong messages

## Local Port Health

The Forwarding line shows the health status of your local target:

- **healthy** - local port is responding
- Status is checked automatically

## Keyboard Shortcuts

| Key      | Action                                      |
| -------- | ------------------------------------------- |
| `Ctrl+C` | Quit the client gracefully                  |
| `Ctrl+I` | Toggle extra session details                |
| `Ctrl+U` | Trigger immediate update check              |

## Color Output

The dashboard uses ANSI colors for readability:

- **Cyan** - public URL, info notices
- **Green** - 2xx status codes, online status
- **Yellow** - 3xx/4xx status codes, warning notices, connecting status
- **Red** - 5xx status codes, blocked requests
- **Dim** - timestamps, separators, secondary info

## See Also

- [Client Configuration](client-configuration.md) - all client flags and env vars
- [Auto-Update](auto-update.md) - update notifications and Ctrl+U
- [Web Application Firewall](waf.md) - WAF rules and blocked request details
