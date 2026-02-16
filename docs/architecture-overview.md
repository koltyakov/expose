# Architecture Overview

How **expose** routes public HTTPS traffic to your local machine through a WebSocket tunnel.

## High-Level Flow

```mermaid
flowchart LR
    Browser["Browser"] -- "HTTPS request<br/>myapp.example.com" --> Server
    Server["expose server<br/>(TLS + routing)"] -- "WebSocket<br/>tunnel" <--> Client["expose client"]
    Client -- "HTTP<br/>127.0.0.1:PORT" --> App["Local app"]
```

## Request Lifecycle

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as expose server
    participant C as expose client
    participant A as Local app

    C->>S: POST /v1/tunnels/register (API key)
    S-->>C: tunnel_id + ws_url
    C->>S: WebSocket connect /v1/tunnels/connect

    B->>S: HTTPS GET myapp.example.com/path
    S->>S: Match hostname → tunnel session
    S->>C: Forward request over WebSocket
    C->>A: HTTP GET 127.0.0.1:3000/path
    A-->>C: HTTP response
    C-->>S: Forward response over WebSocket
    S-->>B: HTTPS response
```

## Components

| Component          | Role                                                                          |
| ------------------ | ----------------------------------------------------------------------------- |
| **Server**         | Terminates TLS, manages ACME certs, authenticates clients, routes by hostname |
| **Client**         | Registers tunnel, holds WebSocket, proxies requests to local port             |
| **Store (SQLite)** | Persists API keys, domains, tunnel state                                      |
| **Hub**            | In-memory map of active WebSocket sessions for fast hostname lookup           |

## Tunnel Types

| Type          | Hostname                                               | Lifetime                                       |
| ------------- | ------------------------------------------------------ | ---------------------------------------------- |
| **Temporary** | Auto-generated 6-char slug (e.g. `k3xnz3.example.com`) | Cleaned up after disconnect + retention period |
| **Named**     | User-chosen (e.g. `myapp.example.com`)                 | Persists across reconnects                     |

## Reliability

- Client sends periodic **keepalive pings** over WebSocket
- Server **expires stale sessions** via background janitor
- Client **auto-reconnects** with exponential backoff on disconnect
- Temporary domains and stale cert cache entries are **purged automatically**
