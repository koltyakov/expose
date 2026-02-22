# Client Configuration

Complete reference for all client flags, environment variables, and credential management.

## Commands

| Command                              | Description                             |
| ------------------------------------ | --------------------------------------- |
| `expose http <port>`                 | Expose a local port (temporary subdomain) |
| `expose http --domain=myapp <port>`  | Expose with a named subdomain           |
| `expose http --protect <port>`       | Expose with password protection         |
| `expose login`                       | Save server URL and API key             |
| `expose up`                          | Start routes from `expose.yml`          |
| `expose up init`                     | Create `expose.yml` via wizard          |
| `expose update`                      | Update to the latest release            |

## Flags & Environment Variables

| Flag        | Env Variable       | Description                                        |
| ----------- | ------------------ | -------------------------------------------------- |
| `--port`    | `EXPOSE_PORT`      | Local HTTP port on `127.0.0.1` (positional arg)   |
| `--domain`  | `EXPOSE_SUBDOMAIN` | Requested subdomain label (e.g. `myapp`)           |
| `--server`  | `EXPOSE_DOMAIN`    | Server URL (e.g. `example.com`)                    |
| `--api-key` | `EXPOSE_API_KEY`   | API key for authentication                         |
| `--protect` | -                  | Enable HTTP Basic Auth for this tunnel             |
| -           | `EXPOSE_USER`      | Basic Auth username (default: `admin`)             |
| -           | `EXPOSE_PASSWORD`  | Basic Auth password                                |
| -           | `EXPOSE_AUTOUPDATE`| Enable automatic self-update (`true`/`1`/`yes`)   |

## Credential Resolution

The client resolves server URL and API key from multiple sources, with this priority:

1. **CLI flags** (`--server`, `--api-key`) — highest priority
2. **Environment variables** (`EXPOSE_DOMAIN`, `EXPOSE_API_KEY`)
3. **`.env` file** in the current directory
4. **Saved credentials** from `expose login` (`~/.expose/settings.json`) — lowest priority

This means you can `expose login` once and never pass credentials again, or override per-command with flags or env vars.

## Login

Save credentials locally so you don't need `--server` and `--api-key` on every command:

```bash
expose login --server example.com --api-key <KEY>
```

In an interactive terminal, if `--server` or `--api-key` is omitted, the CLI prompts for missing values.

Credentials are stored in:

| OS            | Path                                  |
| ------------- | ------------------------------------- |
| macOS / Linux | `~/.expose/settings.json`             |
| Windows       | `%USERPROFILE%\.expose\settings.json` |

File permissions are set to `0600` (owner-only read/write).

## Tunnel Types

### Temporary (default)

When `--domain` is not set, the server allocates a short random hostname:

```bash
expose http 3000
# → https://k3xnz3.example.com
```

Temporary tunnels are cleaned up after disconnect. See [Temporary Host Allocation](temporary-host-allocation.md) for how slugs are generated.

### Named

Request a stable subdomain that persists across reconnects:

```bash
expose http --domain=myapp 3000
# → https://myapp.example.com
```

## Password Protection

Add HTTP Basic Auth in front of your tunnel:

```bash
# Interactive — prompts for password
expose http --domain=myapp --protect 3000

# Non-interactive — password from env
EXPOSE_USER=admin EXPOSE_PASSWORD=secret expose http --domain=myapp 3000
```

> **Note**: If your app already has its own authentication, `--protect` adds a second auth layer. This can cause double-auth prompts or break OAuth callback flows that expect direct access.

## Multi-Route Config (`expose up`)

For projects with multiple services, use `expose.yml`:

```bash
expose up init    # guided wizard
expose up         # start all routes
expose up -f ./custom.yml
```

See [expose up](expose-up.md) for the full config reference.

## Client Dashboard

The client shows a real-time terminal UI with:

- Connection status and uptime
- Public URL and local target
- Request log with method, path, status, and duration
- Latency percentiles (P50/P90/P95/P99)
- Active clients and WebSocket connection count
- WAF blocked count (when WAF is enabled on server)
- Update availability notifications

See [Client Dashboard](client-dashboard.md) for details.

## Keyboard Shortcuts

| Key       | Action                    |
| --------- | ------------------------- |
| `Ctrl+C`  | Quit                      |
| `Ctrl+U`  | Trigger manual update     |

## Auto-Update

When `EXPOSE_AUTOUPDATE=true`, the client checks for updates on startup and periodically (every 30 minutes). Updates are downloaded and applied automatically, then the process restarts.

See [Auto-Update](auto-update.md) for configuration details.

## Reconnection

The client automatically reconnects when the connection drops:

- Exponential backoff between retry attempts
- Periodic keepalive pings maintain the connection
- Server version changes trigger an update check (when auto-update is enabled)

## See Also

- [Quick Start](quick-start.md) — get started in 5 minutes
- [API Keys](api-keys.md) — create and manage keys
- [Local Testing](local-testing.md) — single-machine E2E with `127.0.0.1.sslip.io`
