# `expose up`

Run multiple HTTP routes from a single project config (`expose.yml`).

Use `expose up` when you want to:
- expose more than one local service at once
- mount multiple services under one subdomain (for example `/` + `/api`)
- keep a reusable project config in version control

## Commands

Start routes from the default config file:

```bash
expose up
```

Start routes from a custom file:

```bash
expose up -f ./expose.yml
```

Create a config interactively:

```bash
expose up init
```

Custom path for the generated config:

```bash
expose up init -f ./expose.yml
```

## Example `expose.yml`

```yaml
version: 1

protect:
  user: admin
  password: EXPOSE_PASSWORD

tunnels:
  - name: frontend
    subdomain: myapp
    port: 3000
    path_prefix: /
    strip_prefix: false

  - name: api
    subdomain: myapp
    port: 8080
    path_prefix: /api
    strip_prefix: true
```

This publishes:
- `https://myapp.<base-domain>/` -> `http://127.0.0.1:3000/`
- `https://myapp.<base-domain>/api/*` -> `http://127.0.0.1:8080/*` (prefix stripped)

## Config Reference

Top-level fields:

- `version` (optional, defaults to `1`; only `1` is supported)
- `server` (optional) - explicit server URL, e.g. `https://example.com`
- `api_key` (optional) - client API key
- `protect` (optional) - shared Basic Auth for all routes in this file (`access` is also accepted for compatibility)
- `tunnels` (required) - one or more routes

### `protect`

Applies the same HTTP Basic Auth challenge to every tunnel started by this config.

- `user` (optional, default `admin`)
- `password` (optional) - literal password or env var name

Notes:
- If `password` is uppercase (for example `EXPOSE_PASSWORD`) and an environment variable with that name exists, `expose up` uses the env var value.
- If no environment variable exists with that name, the `password` value is used as the literal password.
- If protection is enabled and no password is provided in YAML, `expose up` falls back to `EXPOSE_PASSWORD`.
- Legacy `password_env` is still accepted for older configs, but `password` is the canonical field.
- In interactive terminals, `expose up` prompts for a password if protection is enabled and none is available.

### `tunnels[]`

Each entry defines one public host/path route to one local port.

- `name` (optional) - label used in summaries/logs
- `subdomain` (required) - hostname label under your base domain (example: `myapp`)
- `port` (required) - local HTTP port on `127.0.0.1`
- `path_prefix` (optional, default `/`) - public path mount
- `strip_prefix` (optional, default `false`) - remove `path_prefix` before forwarding

Validation / behavior:
- `subdomain` is normalized (lowercased, scheme/path removed); prefer a hostname label like `myapp`
- `path_prefix` is normalized (`/api/` becomes `/api`)
- `path_prefix` cannot include query strings or fragments
- duplicate `(subdomain, path_prefix)` routes are rejected

## Routing Behavior

- Routes are grouped by `subdomain`.
- `expose up` starts one public tunnel per subdomain.
- Requests are matched by path prefix within that subdomain.
- Longest `path_prefix` wins.
- Prefix matching is segment-aware: `/api` matches `/api` and `/api/users`, but not `/apiv2`.
- If no route matches, the local router returns `404`.

## Credentials and `.env`

`expose up` loads `.env` from the current directory and uses `EXPOSE_*` variables that are not already set in the environment.

Credential sources:

1. `server` / `api_key` in `expose.yml` (if set)
2. `EXPOSE_DOMAIN` / `EXPOSE_API_KEY` from environment or `.env`
3. Saved credentials from `expose login` (`~/.expose/settings.json`)

This means you can keep `expose.yml` non-secret and rely on `expose login` or `.env`.

## Common Patterns

### Single service (stable subdomain)

```yaml
version: 1
tunnels:
  - subdomain: app
    port: 3000
```

Run:

```bash
expose login --server https://example.com --api-key <key>
expose up
```

### Frontend + API on one host

```yaml
version: 1
tunnels:
  - name: web
    subdomain: myapp
    port: 3000
    path_prefix: /
  - name: api
    subdomain: myapp
    port: 8080
    path_prefix: /api
    strip_prefix: true
```

### Multiple apps on different subdomains

```yaml
version: 1
tunnels:
  - subdomain: app
    port: 3000
  - subdomain: admin
    port: 4000
  - subdomain: docs
    port: 4321
```

## Notes

- `expose up init` requires an interactive terminal.
- `expose up` is project-oriented; `expose http` is still the fastest path for one-off tunnels.
- Tunnel protection here is per-config (shared across all routes), not per-route.
