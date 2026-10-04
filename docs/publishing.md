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

Publishing shows archive and upload progress on stderr, including file counts, original and compressed sizes, upload destination, and elapsed time. Terminal progress updates in place. Redirected output records only stage starts and completion summaries. `--json` suppresses progress and prints only the publication metadata on success.

After uploading, a success summary highlights the public URL and shows the expiry in your local timezone. Terminal output uses color, unless `NO_COLOR` is set. Redirected output stays plain text.

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

Without `--domain`, the server generates a random hashed subdomain on the first publication. Publishing the same folder again reuses its existing hostname. With `--domain=docs`, the site uses `docs.<server-base-domain>`, following the same convention as `expose http 3000 --domain=docs`. Publishing to that domain again replaces the site owned by your API key. After stopping a tunnel, you can publish to its hostname using the same API key. Publishing replaces the stopped tunnel's reservation and invalidates its old sessions and connection tokens. A hostname reserved by another API key or by a connected tunnel cannot be claimed.

Republishing makes the remote site match the local folder's public files. Files absent from the local folder are removed. By default, only new or changed file contents are uploaded. The server validates and prepares the site in a separate directory, then switches to it. A rejected upload leaves the current site intact. The site's URL and identity stay the same, and its TTL restarts from the new publication time. If a folder has multiple publications, use `--domain` to choose which one to replace. An explicit new domain creates a separate publication.

`--ttl` accepts positive Go durations such as `30m`, `24h`, or `168h`. The default is 7 days, enforced by the server when TTL is omitted. Expired sites stop serving immediately. The server's periodic cleanup removes their files and hostname reservations, including expirations that occurred while the server was offline.

Listing, stats access, and deletion are scoped to the authenticated API key. Revoking a key also stops its published sites from serving.

To list tunnels alongside published sites, use [`expose list`](client-configuration.md#list-tunnels-and-published-sites). Add `--json` for scripts.

All commands accept `--server` and `--api-key`, or use the usual environment variables and saved login. `--json` produces structured upload, listing, and deletion output.

## Incremental publishing

Publishing is incremental by default. Use `--full` to upload every public file without fetching the published file list or comparing checksums:

```bash
expose pub ./dist
expose pub ./dist --domain=docs --ttl=24h
expose pub ./dist --full
```

The client fetches the published files' relative paths, sizes, and SHA-256 checksums, then hashes the local public files and compares their contents. Only new and updated files go into the upload. Files removed locally are deleted remotely, and unchanged files are reused from the server's existing publication. Before archiving, the CLI shows file counts and total uncompressed sizes for new, updated, deleted, and unchanged files. New and updated sizes use the current local contents; deleted sizes use the published contents being removed.

The first incremental publication uploads all public files. A deletion-only upload sends no file contents. If nothing changed, publishing sends only the target manifest to renew the site's TTL, without transferring file contents. The `Published` summary still shows the public URL and updated expiry. `--json` suppresses progress and returns publication metadata.

Incremental updates use the same atomic directory switch as full uploads. The server validates checksums and limits for the complete resulting site, including reused files. A failed update leaves the current publication intact. If another upload or deletion changes the publication after the file comparison, the server rejects the stale update with HTTP `412`. Run the command again to compare against the latest publication.

Both client and server must support incremental publishing. An older server produces an error explaining how to upgrade or publish with `--full`. Full uploads use the original gzip-compressed tar format and replace the entire remote site without requesting a file list.

## Watch local changes

Use `--watch` to publish the folder, keep the live stats dashboard open, and automatically publish local changes:

```bash
expose pub ./dist --watch
expose pub ./dist --domain=docs --watch --ttl=24h
expose pub ./site --watch --staged
```

Watch mode checks public file metadata every 250 ms and waits for 200 ms of quiet before comparing checksums and uploading changes. New files, edits, renames, and deletions are detected recursively. Blocked paths do not trigger uploads. A metadata-only change with identical contents does not upload or renew the TTL. The dashboard's New, Updates, and Deleted counts accumulate across successful uploads in the current watch session, including the initial publish. Failed attempts do not count. Creating and then deleting a file increments both New and Deleted.

New zero-byte files are ignored until they have content, including during the initial watch upload. Creating an empty file in an editor and then saving content counts as one new file, not a new file followed by an update. Already-published files can still be emptied or deleted. One-shot publishing includes empty files as usual.

Add `--staged` to publish the Git index for the selected folder, including unchanged tracked files. Staging additions, updates, renames, and deletions triggers uploads. Staged contents are used even if the working copy has newer unstaged edits. Unstaging also updates the publication to match the index: edited or deleted files return to their HEAD versions, and new files are removed. Untracked files, unstaged edits, and index changes outside the selected folder are ignored. Committing alone does not trigger an upload because it leaves the index contents unchanged.

`--staged` requires `--watch` and Git. The folder must be in a Git working tree, and its root `index.html` must be in the index.

The dashboard shows hosting stats, the local folder, current archive/upload progress, the last publication time, and change counts and sizes. Stats keep refreshing while an upload is in progress. Saves during an upload are queued for another incremental comparison afterward. Successful updates renew the TTL using the original `--ttl`, or the server default if omitted.

Temporary network failures, revision conflicts, and incomplete builds are retried without replacing the live site. A missing root `index.html` pauses publishing until it returns. Deleting or expiring the remote publication, or losing access to it, stops watch mode. Updates are pinned to the original publication identity so hostname reuse cannot redirect them to another site.

Press **Ctrl+C** to stop watching. The remote site stays hosted. `--watch` cannot be combined with `--full` because watched updates are always incremental.

For scripts, `expose pub ./dist --watch --json` streams NDJSON events with a `type` of `published`, `stats`, or `error`. Publication events include the site metadata and file counts and byte totals under `changes.new`, `changes.updated`, `changes.deleted`, and `changes.unchanged`. Progress text is suppressed.

## Live stats connection

Connect by local folder or subdomain using the API key that owns the publication:

```bash
expose pub connect ./dist
expose pub connect --domain=docs
```

The dashboard refreshes once per second and shows:

- Public URL, expiry, server version, and connection round-trip time
- Published file count and total uncompressed size, shown between Public URL and Published
- HTTP request count and recent request paths, methods, status codes, and durations
- Response-body bytes sent and the current transfer rate
- Tracked visitors and visitors active within the last minute, plus online sockets when `--ws` is enabled
- Request-latency p50 and p95 across the last 1,024 handled requests
- WAF blocks and audit-only matches, counted separately

Press **Ctrl+C** to disconnect. The site stays hosted, and connecting does not change its TTL. The client reconnects after temporary network or server failures. If the site expires or is deleted, or the API key is revoked, the connection stops. Republishing preserves the connection and counters.

For scripts, stream one JSON snapshot per line:

```bash
expose pub connect --domain=docs --json
```

Stats collect on the server even when no dashboard is connected. Tracked visitor identities are stored in SQLite under the site's stable identity, so the total survives full and incremental republishing, TTL renewal, and server restarts. Removing a site, either explicitly or through TTL cleanup, deletes its visitor identities. Publishing it again starts a new count. Other counters, recent activity, and request history are held in memory and reset on server restart. Each site retains its last 20 request/WAF events and tracks up to 10,000 distinct visitors, identified by a hash of IP address and User-Agent. The dashboard reports when this tracking limit is reached. Active visitor counts then cover only tracked visitors. The terminal shows the newest requests that fit; JSON snapshots include all retained events.

File totals describe the current hosted publication, not the local folder or the compressed upload. They refresh after full and incremental updates and are included in JSON snapshots as `file_count` and `file_bytes`. The server caches these totals per immutable publication directory, so stats polling does not re-read file contents.

Request logs omit query strings, headers, and raw visitor identifiers. Traffic counts HTTP response-body bytes from the static handler, excluding TLS/HTTP headers and responses generated by the WAF. WAF-blocked requests have their own counter and do not increment the handled HTTP request count. `expose pub list` shows publication metadata, while `connect` shows live stats.

### Track open pages

Add `--ws` when publishing to keep open pages visible as active visitors, even when they do not download more files:

```bash
expose pub ./dist --ws
expose pub ./dist --watch --ws
expose pub connect ./dist
```

This is off by default. When enabled, the server appends a small ES5-compatible same-site script to HTML responses, including SPA fallbacks. Uploaded files and their checksums stay unchanged. The script opens a WebSocket to the published hostname while the page is visible. The server sends a small ping every 20 seconds; the browser answers automatically. Heartbeats do not add HTTP requests, response bytes, or request-log entries.

The Visitors field adds a separate online count, for example `12 tracked, 4 active (last minute), 3 online`. Online counts live sockets from visible tabs; tracked and recently active visitors use the existing IP address and User-Agent identity. Two visible tabs with the same identity count as two online sockets and one visitor. JSON stats expose the socket count as `active_sockets`. Unlike tracked visitors, this count is not capped by the historical visitor-tracking limit.

Closing a tab or browser, switching to another tab, or minimizing the browser closes the socket through page lifecycle and visibility events. Hidden tabs count as disconnected and do not retry until visible again. The server removes each socket from the online count as soon as it disconnects, even if its visitor recently downloaded files. The dashboard reflects this on its next one-second refresh. Recent visitor activity still expires one minute after the last request or heartbeat. Browsers without the Page Visibility API can still disconnect on page exit.

The client reconnects when the page becomes visible, after network interruptions, and when a page returns from the browser's back/forward cache. Crashes, lost networks, and browsers that suspend without delivering a lifecycle event cannot guarantee an immediate close notification; their sockets time out after 55 seconds without a heartbeat.

`--ws` works with full, incremental, and watched uploads. Include it on each publish command to keep it enabled. Republishing without it, or with `--ws=false`, disables injection and closes existing presence sockets. The setting survives server restarts. Cached pages must have received the injected script at least once to report activity.

With `--ws`, `/_expose/presence.js` and `/_expose/presence` are reserved for the client script and WebSocket. The endpoint accepts only same-host browser origins, limits message size and connection counts, and exchanges control frames only. A site's Content Security Policy must allow the same-site script and the WebSocket connection, for example `script-src 'self'` and `connect-src 'self' wss://docs.example.com`. Expose does not alter that policy.

## SPA routing

The root path serves `index.html`. For a path such as `/docs/getting-started`, the server tries these files in order:

1. `docs/getting-started`, if it is a regular file
2. `docs/getting-started.html`
3. `docs/getting-started/index.html`
4. The root `index.html`

Trailing slashes use the same fallback order. Exact assets keep their content type. `GET` and `HEAD` support conditional requests and byte ranges. Directory listings are disabled. Expose reserves `/_expose/v1` and its descendants and `/_expose/healthz` for service APIs. Sites can serve their own `/v1/*` and `/healthz` paths.

Published sites use the server's existing WAF, HTTPS certificate handling, trusted-proxy settings, and optional per-host/client-IP public rate limits.

### HTTP caching

Published files, including HTML and SPA fallbacks, send `Cache-Control: no-cache`. Browsers and shared caches may store responses but must revalidate before reuse, as specified by [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4). This keeps republished content fresh and requires caches to check whether a site is still available after expiry or deletion.

Each file has a quoted, publication-specific `ETag`. Conditional `GET` and `HEAD` requests with a matching `If-None-Match` receive `304 Not Modified` without transferring the file again. Republishing changes the ETags even if file sizes and modification times match the previous upload. `Last-Modified` and byte-range requests remain supported. Missing or blocked paths send `Cache-Control: no-store`.

## Upload guards and limits

The CLI silently skips blocked paths, including the entire contents of blocked directories. Publishing continues with the remaining files. The server rejects archives containing blocked paths.

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

This limit applies to the sum of all files, including on replacement uploads. Oversized sites receive HTTP `413`, their staging files are removed, and an existing publication stays intact. Compressed uploads are limited to 256 MiB and archives to 20,000 entries. Both the client and server must support this archive limit; older versions cap compressed uploads at 100 MiB. The 256 MiB cap leaves room for archive overhead when publishing 200 MiB of incompressible files. The CLI also has a 500 MiB extracted-size ceiling. Invalid archives never become routable. There is no upload-policy override for blocked files.

## Server storage

Site metadata lives in SQLite. Files default to `<database-path>.sites`, for example `./expose.db.sites`. Set `EXPOSE_PUBLISH_DIR` or `expose server --publish-dir /srv/expose/sites` to choose another directory. Keep both the database and site directory on persistent storage and back them up together.

The server removes abandoned upload directories and orphaned site directories older than 24 hours during cleanup.

## HTTP API

All endpoints require `Authorization: Bearer <API-key>`.

| Method | Path | Operation |
| --- | --- | --- |
| `POST` | `/_expose/v1/sites?domain=docs&ttl=24h&ws=true` | Upload a gzip-compressed tar body. All query parameters are optional; `ws` defaults to false |
| `GET` | `/_expose/v1/sites/files?domain=docs` | List owned file paths, SHA-256 checksums, and sizes, with a publication revision in `ETag`. Use `source_id` instead of `domain` to select by folder |
| `POST` | `/_expose/v1/sites?domain=docs&incremental=true` | Upload a gzip-compressed delta archive with `If-Match` set to the file listing's `ETag` |
| `GET` | `/_expose/v1/sites` | List sites owned by the key |
| `GET` | `/_expose/v1/sites/{subdomain}` | Get site metadata |
| `GET` | `/_expose/v1/sites/{subdomain}/stats` | Get an owner-only live stats snapshot; expired or deleted sites return `404` |
| `DELETE` | `/_expose/v1/sites/{subdomain}` | Delete files and release the hostname |

Metadata contains the internal storage `id`, `hostname`, `created_at`, the `ws` boolean, optional `expires_at`, and optional `source_id`. The CLI sends `source_id` as a query parameter when uploading to associate the publication with its local folder. Commands accept a folder or `--domain`, so the internal ID is not needed. Listing returns an array. Creating a site returns `201`; replacing it returns `200`; deletion returns `204`. Domain conflicts return `409`.

File listings return a JSON array of `{ "path": "index.html", "checksum": "<64 lowercase SHA-256 hex characters>", "size": 123 }` entries. If no publication matches under the authenticated key, the response is an empty array with `ETag: "new"`. File listings are not cached. A `domain` selector takes precedence over `source_id` when both are provided.

An incremental tar archive starts with a regular `.expose-manifest.json` entry containing the complete target file array, bounded to 8 MiB and 20,000 files. Remaining entries contain only new or changed regular files. Paths omitted from the target manifest are deletions. The control entry is validated as metadata and never written into the published site. Missing `If-Match` returns `428`; a changed revision returns `412`. Other archive guards and site-size limits still apply.

Watch updates also send `site_id` to pin the original publication. If the selected publication no longer has that identity, the upload is rejected with `404` before committing any changes.
