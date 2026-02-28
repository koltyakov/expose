# Client Configuration

Complete reference for all client flags, environment variables, and credential management.

## Commands

| Command                              | Description                             |
| ------------------------------------ | --------------------------------------- |
| `expose http <port>`                 | Expose a local port (temporary subdomain) |
| `expose http --domain=myapp <port>`  | Expose with a named subdomain           |
| `expose http --protect <port>`       | Expose with password protection         |
| `expose static [dir]`                | Expose a static directory               |
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
| `--allow`   | -                  | Allow blocked static paths matching a glob pattern |
| -           | `EXPOSE_USER`      | Basic Auth username (default: `admin`)             |
| -           | `EXPOSE_PASSWORD`  | Basic Auth password                                |
| -           | `EXPOSE_AUTOUPDATE`| Enable automatic self-update (`true`/`1`/`yes`)   |

## Credential Resolution

The client resolves server URL and API key from multiple sources, with this priority:

1. **CLI flags** (`--server`, `--api-key`) - highest priority
2. **Environment variables** (`EXPOSE_DOMAIN`, `EXPOSE_API_KEY`)
3. **`.env` file** in the current directory
4. **Saved credentials** from `expose login` (`~/.expose/settings.json`) - lowest priority

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
# Interactive - prompts for password
expose http --domain=myapp --protect 3000

# Non-interactive - password from env
EXPOSE_USER=admin EXPOSE_PASSWORD=secret expose http --domain=myapp 3000
```

> **Note**: If your app already has its own authentication, `--protect` adds a second auth layer. This can cause double-auth prompts or break OAuth callback flows that expect direct access.

## Static Files

Expose the current directory:

```bash
expose static

# or choose a directory explicitly
expose static ./public
```

`expose static` starts a local static web server on an ephemeral loopback port and tunnels that server the same way `expose http` tunnels an existing app. It also reuses the same `--domain`, `--server`, `--api-key`, and `--protect` flags.

If you omit `--domain`, static mode derives a stable default subdomain from the machine id plus the absolute folder path. That means the same folder on the same machine gets the same public hostname on later runs, and a hostname conflict usually means that exact folder is already being served.

For safety, static mode does not serve:

- Hidden files such as `.env`
- Hidden directories such as `.git/`
- Common backup/editor artifacts such as `file.txt.bak`, `file.orig`, or `file~`

When the tunnel is public (no `--protect`), static mode also only serves a conservative set of browser-friendly/static document file types by default, including:

- HTML, CSS, JavaScript, JSON, source maps, WebAssembly, fonts, and common images
- Markdown, text, PDF, ZIP/tar archives
- Office-style documents such as `.docx`, `.xlsx`, `.pptx`, and OpenDocument variants

Markdown behavior:

- Requests for `.md` and `.markdown` files are rendered as formatted HTML pages instead of raw source.
- Fenced `mermaid` code blocks are upgraded automatically with Mermaid client-side rendering.
- Other fenced code blocks, headings, lists, links, quotes, and inline code are styled for readability.

If you need to serve arbitrary file types, use `--protect`.

Folder behavior:

- If a requested folder contains `index.html`, that file is served.
- Folder listings are disabled by default.
- Use `--folders` to allow directory listings when no `index.html` exists.

SPA behavior:

```bash
expose static --spa ./dist
```

With `--spa`, unresolved `GET` and `HEAD` routes fall back to the root `index.html`, unless the route already resolves to a real file or to a folder containing its own `index.html`.

If you intentionally need one of those paths, allow it explicitly:

```bash
expose static --allow '.well-known/**' ./public
```

`--allow` is repeatable and matches paths relative to the exposed directory. Use it carefully, because it overrides the default static-mode blocklist and public file-type restrictions.

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

- [Quick Start](quick-start.md) - get started in 5 minutes
- [API Keys](api-keys.md) - create and manage keys
- [Local Testing](local-testing.md) - single-machine E2E with `127.0.0.1.sslip.io`
