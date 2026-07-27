# Static Sites

Use `expose static` to publish a local directory as a static website through your expose server.

## Quick Start

Expose the current directory:

```bash
expose static
```

Expose a specific directory:

```bash
expose static ./public
```

Static mode starts a local loopback web server, then tunnels it the same way `expose http` tunnels an existing app.

## Common Flags

| Flag        | Description                                                      |
| ----------- | ---------------------------------------------------------------- |
| `--dir`     | Directory to serve (defaults to `.`)                             |
| `--domain`  | Requested public subdomain                                       |
| `--server`  | Server URL                                                       |
| `--api-key` | API key                                                          |
| `--protect` | Enable tunnel protection (`form` by default, `basic` via `--protect=basic`) |
| `--allow`   | Allow blocked paths matching a glob pattern                      |
| `--folders` | Enable directory listings when no directory index exists         |
| `--spa`     | Fallback unresolved `GET`/`HEAD` routes to the root `index.html` |

Examples:

```bash
expose static --domain=docs ./site
expose static --protect ./private-docs
expose static --spa ./dist
expose static --folders ./downloads
expose static --allow '.well-known/**' ./public
```

## Default Hostname

If you omit `--domain`, static mode derives a stable default subdomain from:

- the local machine id
- the absolute folder path

That means the same folder on the same machine gets the same hostname on later runs. If that hostname is already active, it usually means that same folder is already being served.

## Security Defaults

Static mode blocks these by default:

- hidden files such as `.env`
- hidden directories such as `.git/`
- common backup/editor artifacts such as `file.bak`, `file.orig`, `file~`

When the tunnel is public (no `--protect`), static mode also restricts serving to a conservative set of browser-friendly/static document types, including:

- HTML, CSS, JavaScript, JSON, source maps, WebAssembly, fonts, and common images
- Markdown, text, PDF, ZIP/tar archives
- Office/OpenDocument files such as `.docx`, `.xlsx`, `.pptx`, `.odt`

If you need arbitrary file types, use `--protect`.

### `--allow`

`--allow` is repeatable and matches paths relative to the served directory.

Example:

```bash
expose static --allow '.well-known/**' ./public
```

Use it carefully because it overrides the default path blocklist and public file-type restriction.

`EXPOSE_WAF_IGNORE_PATHS` affects only the server-side WAF. It does not override
the static server's hidden-file policy; use `--allow` as well when intentionally
serving a hidden static path.

## Folder Behavior

- Directory indexes are selected in this order: `index.html`, `README.md`, then `README.markdown`.
- A README selected as the directory index is rendered as Markdown.
- Directory listings are disabled by default.
- Use `--folders` to enable listings when no directory index exists.

Symlinks are resolved within the published root. A symlink cannot be used to serve a target outside that root.

## SPA Behavior

For client-side routers:

```bash
expose static --spa ./dist
```

With `--spa`, unresolved `GET` and `HEAD` requests fall back to the root `index.html`, unless the path already resolves to:

- a real file
- a directory with its own directory index

## Markdown Rendering

Requests for `.md` and `.markdown` files are rendered as HTML pages.

Supported behavior includes:

- GitHub-like page styling
- headings, lists, links, blockquotes, tables, and inline code
- language-aware fenced code block formatting for common languages
- Mermaid rendering for fenced `mermaid` blocks
- first `#` heading used as the page title
- allowlisted raw HTML with sanitized tags, attributes, and URL schemes; unsafe HTML is not emitted as active markup

Rendered Markdown pages inherit the nearest favicon found in their directory or a parent directory. Recognized names include `favicon.svg`, `favicon.png`, `favicon.ico`, common JPEG/WebP variants, and `apple-touch-icon.png`. If none exists, `/favicon.ico` uses expose's embedded fallback icon.

## Related Guides

- [Client Configuration](client-configuration.md)
- [Quick Start](quick-start.md)
- [TLS Modes](tls-modes.md)
