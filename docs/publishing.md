# Publishing static sites

`expose pub` uploads a static site to your server and hosts it there. It supports plain HTML sites, generated documentation, and SPAs. The CLI validates the folder, creates a gzip-compressed tar archive, uploads it, and exits. The server validates and extracts the archive before making the site available. Hosting continues after the client disconnects and after server restarts.

## Publish and manage sites

Publish the folder containing your site's files. For sites with a build step, use the build output folder. A root `index.html` is required.

```bash
expose login
expose pub ./dist
expose pub ./dist --domain=docs --ttl=24h
expose pub list
expose pub list --json
expose pub connect ./dist
# Or view stats by subdomain:
expose pub connect --domain=docs
expose pub delete ./dist
# Or select the publication by subdomain:
expose pub delete --domain=docs
```

Positional arguments refer to local folders. To select a publication by subdomain, use `--domain=docs` for `docs.example.com`. Automatically generated hashed subdomains work the same way.

### Unpublish a site

Find the site, then unpublish it using the same API key that published it:

```bash
expose pub list
expose pub delete ./dist
# Or:
expose pub delete --domain=docs
```

Unpublishing removes the files from the server and releases the hostname for reuse. It permanently deletes the publication. Run `expose pub ./dist` to publish the folder again.

Use `expose pub delete --domain=docs --json` for scripts. Success returns `{"subdomain":"docs","unpublished":true}`. A missing site or a site owned by another API key returns an error and a nonzero exit code.

Publishing records a hash of the source folder's canonical absolute path and machine identity. Deleting by folder looks up that identifier on the selected server under your API key. Folder contents may have changed since publishing. If multiple publications match the folder, select one with `--domain`. Use `--domain` from another machine, if the folder was moved or removed, or for older publications without a folder identifier. Provide either a folder or `--domain`, not both.

### Hostnames and expiry

Without `--domain`, the server generates a random hashed subdomain on the first publication. Publishing the same folder again reuses its existing hostname. With `--domain=docs`, the site uses `docs.<server-base-domain>`, following the same convention as `expose http 3000 --domain=docs`. Publishing to that domain again replaces the site owned by your API key. A hostname reserved by another API key or by a tunnel cannot be claimed.

Republishing replaces the entire remote folder. Files absent from the new upload are removed. The server validates and extracts the upload into a separate directory, then switches the site to it. A rejected upload leaves the current site intact. The site's URL and identity stay the same, and its TTL restarts from the new publication time. If a folder has multiple publications, use `--domain` to choose which one to replace. An explicit new domain creates a separate publication.

`--ttl` accepts positive Go durations such as `30m`, `24h`, or `168h`. The default is 7 days, enforced by the server when TTL is omitted. Expired sites stop serving immediately. The server's periodic cleanup removes their files and hostname reservations, including expirations that occurred while the server was offline.

Listing, stats access, and deletion are scoped to the authenticated API key. Revoking a key also stops its published sites from serving.

All commands accept `--server` and `--api-key`, or use the usual environment variables and saved login. `--json` produces structured upload, listing, and deletion output.

## Live stats connection

Connect by local folder or subdomain using the API key that owns the publication:

```bash
expose pub connect ./dist
expose pub connect --domain=docs
```

The dashboard refreshes once per second and shows:

- Public URL, expiry, server version, and connection round-trip time
- HTTP request count and recent request paths, methods, status codes, and durations
- Response-body bytes sent and the current transfer rate
- Tracked visitors and visitors active within the last minute
- Request-latency p50 and p95 across the last 1,024 handled requests
- WAF blocks and audit-only matches, counted separately

Press **Ctrl+C** to disconnect. The site stays hosted, and connecting does not change its TTL. The client reconnects after temporary network or server failures. If the site expires or is deleted, or the API key is revoked, the connection stops. Republishing preserves the connection and counters.

For scripts, stream one JSON snapshot per line:

```bash
expose pub connect --domain=docs --json
```

Stats collect on the server even when no dashboard is connected. They are held in memory and reset on server restart. Each site retains its last 20 request/WAF events and tracks up to 10,000 distinct visitors, identified by a hash of IP address and User-Agent. The dashboard reports when this tracking limit is reached. Active visitor counts then cover only tracked visitors. The terminal shows the newest requests that fit; JSON snapshots include all retained events.

Request logs omit query strings, headers, and raw visitor identifiers. Traffic counts HTTP response-body bytes from the static handler, excluding TLS/HTTP headers and responses generated by the WAF. WAF-blocked requests have their own counter and do not increment the handled HTTP request count. `expose pub list` shows publication metadata, while `connect` shows live stats.

## SPA routing

The root path serves `index.html`. For a path such as `/docs/getting-started`, the server tries these files in order:

1. `docs/getting-started`, if it is a regular file
2. `docs/getting-started.html`
3. `docs/getting-started/index.html`
4. The root `index.html`

Trailing slashes use the same fallback order. Exact assets keep their content type. `GET` and `HEAD` support conditional requests and byte ranges. Directory listings are disabled. The existing `/v1/` and `/healthz` server paths remain reserved.

Published sites use the server's existing WAF, HTTPS certificate handling, trusted-proxy settings, and optional per-host/client-IP public rate limits.

## Upload guards and limits

Both the CLI and server reject unsafe paths. The CLI checks the complete tree before creating the archive. An unsafe entry fails the upload instead of silently excluding files.

Rejected entries include:

- `node_modules` and `vendor` directories, including nested copies
- Hidden files and directories such as `.env`, `.env.production`, `.git`, and `.ssh`. `.well-known` is allowed, subject to the server WAF
- Common secret filenames, private-key formats, database dumps, and backups
- Symbolic links, hard links in archives, devices, and other special files
- Absolute paths, parent traversal, and backslash-based paths in archives

These are filename and file-type guards. Publish a build output directory containing only public assets. Secrets embedded in JavaScript or other otherwise-allowed files cannot be identified by these checks.

The server limits each site's total extracted file size to **10 MiB** by default. Configure it with `EXPOSE_PUBLISH_MAX_BYTES` or `--publish-max-bytes`, using a positive byte count. For example, allow 25 MiB:

```bash
expose server --publish-max-bytes=26214400
```

This limit applies to the sum of all files, including on replacement uploads. Oversized sites receive HTTP `413`, their staging files are removed, and an existing publication stays intact. Compressed uploads remain limited to 100 MiB and archives to 20,000 entries. The CLI also has a 500 MiB extracted-size ceiling. Invalid archives never become routable. There is no upload-policy override for blocked files.

## Server storage

Site metadata lives in SQLite. Files default to `<database-path>.sites`, for example `./expose.db.sites`. Set `EXPOSE_PUBLISH_DIR` or `expose server --publish-dir /srv/expose/sites` to choose another directory. Keep both the database and site directory on persistent storage and back them up together.

The server removes abandoned upload directories and orphaned site directories older than 24 hours during cleanup.

## HTTP API

All endpoints require `Authorization: Bearer <API-key>`.

| Method | Path | Operation |
| --- | --- | --- |
| `POST` | `/v1/sites?domain=docs&ttl=24h` | Upload a gzip-compressed tar body. Both query parameters are optional |
| `GET` | `/v1/sites` | List sites owned by the key |
| `GET` | `/v1/sites/{subdomain}` | Get site metadata |
| `GET` | `/v1/sites/{subdomain}/stats` | Get an owner-only live stats snapshot; expired or deleted sites return `404` |
| `DELETE` | `/v1/sites/{subdomain}` | Delete files and release the hostname |

Metadata contains the internal storage `id`, `hostname`, `created_at`, optional `expires_at`, and optional `source_id`. The CLI sends `source_id` as a query parameter when uploading to associate the publication with its local folder. Commands accept a folder or `--domain`, so the internal ID is not needed. Listing returns an array. Creating a site returns `201`; replacing it returns `200`; deletion returns `204`. Domain conflicts return `409`.
