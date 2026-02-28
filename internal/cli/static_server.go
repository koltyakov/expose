package cli

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const staticServerShutdownTimeout = 5 * time.Second

type staticFileServer struct {
	server *http.Server
}

type staticServerOptions struct {
	AllowPatterns []string
	AllowFolders  bool
	SPA           bool
	Unprotected   bool
}

func resolveStaticRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("static root must be a directory")
	}
	return absRoot, nil
}

func startStaticFileServer(ctx context.Context, root string, opts staticServerOptions, log *slog.Logger) (*staticFileServer, int, error) {
	absRoot, err := resolveStaticRoot(root)
	if err != nil {
		return nil, 0, err
	}

	policy, err := newStaticAccessPolicy(opts.Unprotected, opts.AllowPatterns)
	if err != nil {
		return nil, 0, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}

	handler := newStaticHandler(absRoot, policy, opts)

	srv := &staticFileServer{
		server: &http.Server{
			Handler: handler,
		},
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && log != nil {
			log.Error("static file server stopped", "err", err)
		}
	}()

	addr, _ := ln.Addr().(*net.TCPAddr)
	if addr == nil {
		return srv, 0, nil
	}
	return srv, addr.Port, nil
}

func (s *staticFileServer) Close() error {
	if s == nil || s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), staticServerShutdownTimeout)
	defer cancel()
	err := s.server.Shutdown(ctx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func newStaticHandler(root string, policy staticAccessPolicy, opts staticServerOptions) http.Handler {
	fsys := staticFileSystem{
		root:   http.Dir(root),
		policy: policy,
	}
	return &staticHandler{
		fsys:         fsys,
		fileServer:   http.FileServer(fsys),
		allowFolders: opts.AllowFolders,
		spa:          opts.SPA,
	}
}

type staticHandler struct {
	fsys         staticFileSystem
	fileServer   http.Handler
	allowFolders bool
	spa          bool
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cleanPath := staticCleanPath(r.URL.Path)
	if h.serveResolvedPath(w, r, cleanPath) {
		return
	}
	if h.spa && staticSPAMethodAllowed(r.Method) && cleanPath != "/index.html" && h.serveSPAIndex(w, r) {
		return
	}
	http.NotFound(w, r)
}

func (h *staticHandler) serveResolvedPath(w http.ResponseWriter, r *http.Request, cleanPath string) bool {
	file, info, ok := h.open(cleanPath)
	if !ok {
		return false
	}
	if !info.IsDir() {
		defer func() { _ = file.Close() }()
		serveStaticOpenedFile(w, r, file, info)
		return true
	}
	_ = file.Close()

	if defaultPath, defaultFile, defaultInfo, ok := h.openDirectoryDefaultFile(cleanPath); ok {
		if staticNeedsDirRedirect(r.URL.Path) {
			_ = defaultFile.Close()
			redirectStaticDirectory(w, r)
			return true
		}
		defer func() { _ = defaultFile.Close() }()
		serveStaticOpenedFileWithName(w, r, defaultPath, defaultFile, defaultInfo)
		return true
	}

	if !h.allowFolders {
		return false
	}
	if staticNeedsDirRedirect(r.URL.Path) {
		redirectStaticDirectory(w, r)
		return true
	}
	h.fileServer.ServeHTTP(w, cloneStaticRequestPath(r, staticDirectoryPath(cleanPath)))
	return true
}

func (h *staticHandler) serveSPAIndex(w http.ResponseWriter, r *http.Request) bool {
	file, info, ok := h.open("/index.html")
	if !ok {
		return false
	}
	if info.IsDir() {
		_ = file.Close()
		return false
	}
	defer func() { _ = file.Close() }()
	serveStaticOpenedFile(w, r, file, info)
	return true
}

func (h *staticHandler) openDirectoryDefaultFile(cleanPath string) (string, http.File, os.FileInfo, bool) {
	for _, name := range []string{"index.html", "README.md", "README.markdown"} {
		filePath := path.Join(cleanPath, name)
		file, info, ok := h.open(filePath)
		if ok && !info.IsDir() {
			return filePath, file, info, true
		}
		if ok {
			_ = file.Close()
		}
	}
	return "", nil, nil, false
}

func (h *staticHandler) open(name string) (http.File, os.FileInfo, bool) {
	file, err := h.fsys.Open(name)
	if err != nil {
		return nil, nil, false
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, false
	}
	return file, info, true
}

func staticSPAMethodAllowed(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func staticNeedsDirRedirect(requestPath string) bool {
	requestPath = strings.TrimSpace(requestPath)
	return requestPath != "" && !strings.HasSuffix(requestPath, "/")
}

func redirectStaticDirectory(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path
	if target == "" {
		target = "/"
	}
	if !strings.HasSuffix(target, "/") {
		target += "/"
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func cloneStaticRequestPath(r *http.Request, pathValue string) *http.Request {
	clone := r.Clone(r.Context())
	clone.URL.Path = pathValue
	clone.URL.RawPath = ""
	return clone
}

func staticDirectoryPath(cleanPath string) string {
	if cleanPath == "" || cleanPath == "/" {
		return "/"
	}
	return cleanPath + "/"
}

func serveStaticOpenedFile(w http.ResponseWriter, r *http.Request, file http.File, info os.FileInfo) {
	serveStaticOpenedFileWithName(w, r, info.Name(), file, info)
}

func serveStaticOpenedFileWithName(w http.ResponseWriter, r *http.Request, name string, file http.File, info os.FileInfo) {
	if staticShouldRenderMarkdown(r.Method, info.Name()) {
		if serveRenderedMarkdownFile(w, r, file, info) {
			return
		}
	}
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func staticShouldRenderMarkdown(method, name string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(name)))
	return ext == ".md" || ext == ".markdown"
}

func serveRenderedMarkdownFile(w http.ResponseWriter, r *http.Request, file http.File, info os.FileInfo) bool {
	body, err := io.ReadAll(file)
	if err != nil {
		return false
	}
	rendered, title, hasMermaid := renderMarkdownDocument(string(body))
	if strings.TrimSpace(title) == "" {
		title = strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
	}
	page, err := buildMarkdownHTMLPage(markdownPageData{
		Title:      title,
		BodyHTML:   template.HTML(rendered),
		HasMermaid: hasMermaid,
	})
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, info.Name()+".html", info.ModTime(), bytes.NewReader(page))
	return true
}

type markdownPageData struct {
	Title      string
	BodyHTML   template.HTML
	HasMermaid bool
}

var markdownPageTemplate = template.Must(template.New("markdown-page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f6f8fa;
      --panel: #ffffff;
      --border: #d0d7de;
      --border-muted: #d8dee4;
      --text: #1f2328;
      --muted: #59636e;
      --accent: #0969da;
      --accent-hover: #0550ae;
      --code-bg: #f6f8fa;
      --code-text: #1f2328;
      --pre-bg: #f6f8fa;
      --quote-border: #d0d7de;
      --quote-bg: transparent;
      --shadow: 0 1px 2px rgba(31, 35, 40, 0.04);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0d1117;
        --panel: #0d1117;
        --border: #30363d;
        --border-muted: #21262d;
        --text: #e6edf3;
        --muted: #8b949e;
        --accent: #58a6ff;
        --accent-hover: #79c0ff;
        --code-bg: rgba(110, 118, 129, 0.22);
        --code-text: #e6edf3;
        --pre-bg: #161b22;
        --quote-border: #3d444d;
        --quote-bg: transparent;
        --shadow: none;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px 16px 48px;
      background: var(--bg);
      color: var(--text);
      font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
    }
    .markdown-body {
      max-width: 980px;
      margin: 0 auto;
      padding: 32px;
      background: var(--panel);
      border: 1px solid var(--border-muted);
      border-radius: 12px;
      box-shadow: var(--shadow);
    }
    .markdown-body > *:first-child {
      margin-top: 0 !important;
    }
    .markdown-body > *:last-child {
      margin-bottom: 0 !important;
    }
    .markdown-body h1,
    .markdown-body h2,
    .markdown-body h3,
    .markdown-body h4,
    .markdown-body h5,
    .markdown-body h6 {
      margin-top: 24px;
      margin-bottom: 16px;
      font-weight: 600;
      line-height: 1.25;
    }
    .markdown-body h1 {
      padding-bottom: 0.3em;
      font-size: 2em;
      border-bottom: 1px solid var(--border);
    }
    .markdown-body h2 {
      padding-bottom: 0.3em;
      font-size: 1.5em;
      border-bottom: 1px solid var(--border);
    }
    .markdown-body h3 { font-size: 1.25em; }
    .markdown-body h4 { font-size: 1em; }
    .markdown-body h5 { font-size: 0.875em; }
    .markdown-body h6 { font-size: 0.85em; color: var(--muted); }
    .markdown-body p,
    .markdown-body ul,
    .markdown-body ol,
    .markdown-body blockquote,
    .markdown-body pre,
    .markdown-body table,
    .markdown-body hr {
      margin-top: 0;
      margin-bottom: 16px;
    }
    .markdown-body ul,
    .markdown-body ol {
      padding-left: 2em;
    }
    .markdown-body li + li {
      margin-top: 0.25em;
    }
    .markdown-body a {
      color: var(--accent);
      text-decoration: none;
    }
    .markdown-body a:hover {
      color: var(--accent-hover);
      text-decoration: underline;
    }
    .markdown-body code {
      padding: 0.2em 0.4em;
      margin: 0;
      border-radius: 6px;
      background: var(--code-bg);
      color: var(--code-text);
      font: 0.82em/1.45 ui-monospace, SFMono-Regular, SFMono, Menlo, Consolas, "Liberation Mono", monospace;
    }
    .markdown-body pre {
      overflow: auto;
      padding: 14px 16px;
      border-radius: 6px;
      background: var(--pre-bg);
      line-height: 1.45;
      tab-size: 4;
      position: relative;
    }
    .markdown-body pre code {
      padding: 0;
      background: transparent;
      color: inherit;
      border-radius: 0;
      font-size: 0.82em;
      display: block;
    }
    .markdown-body pre code[data-lang]::before {
      content: attr(data-lang);
      display: block;
      margin-bottom: 10px;
      color: var(--muted);
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .markdown-body .tok-comment { color: #6e7781; }
    .markdown-body .tok-keyword { color: #cf222e; }
    .markdown-body .tok-string { color: #0a3069; }
    .markdown-body .tok-number { color: #0550ae; }
    .markdown-body .tok-type { color: #953800; }
    .markdown-body .tok-func { color: #8250df; }
    .markdown-body .tok-var { color: #116329; }
    .markdown-body .tok-tag { color: #116329; }
    .markdown-body .tok-attr { color: #953800; }
    .markdown-body .tok-punct { color: var(--muted); }
    @media (prefers-color-scheme: dark) {
      .markdown-body .tok-comment { color: #8b949e; }
      .markdown-body .tok-keyword { color: #ff7b72; }
      .markdown-body .tok-string { color: #a5d6ff; }
      .markdown-body .tok-number { color: #79c0ff; }
      .markdown-body .tok-type { color: #ffa657; }
      .markdown-body .tok-func { color: #d2a8ff; }
      .markdown-body .tok-var { color: #7ee787; }
      .markdown-body .tok-tag { color: #7ee787; }
      .markdown-body .tok-attr { color: #ffa657; }
      .markdown-body .tok-punct { color: #8b949e; }
    }
    .markdown-body blockquote {
      margin-left: 0;
      margin-right: 0;
      padding: 0 0 0 16px;
      color: var(--muted);
      border-left: 0.25em solid var(--quote-border);
      background: var(--quote-bg);
      border-radius: 0;
    }
    .markdown-body blockquote p:last-child {
      margin-bottom: 0;
    }
    .markdown-body hr {
      border: 0;
      height: 1px;
      background: var(--border);
    }
    .markdown-body table {
      width: 100%;
      border-collapse: collapse;
      display: block;
      overflow-x: auto;
    }
    .markdown-body th,
    .markdown-body td {
      padding: 6px 13px;
      border: 1px solid var(--border);
      text-align: left;
    }
    .markdown-body tr:nth-child(2n) {
      background: color-mix(in srgb, var(--code-bg) 70%, transparent);
    }
    .markdown-body img {
      max-width: 100%;
      height: auto;
      background: transparent;
      border-radius: 6px;
    }
    .markdown-body .mermaid {
      padding: 8px;
      border-radius: 6px;
      background: var(--pre-bg);
      overflow-x: auto;
      text-align: center;
    }
    .markdown-body .mermaid svg {
      display: block;
      margin: 0 auto;
    }
    @media (max-width: 768px) {
      .markdown-body {
        padding: 20px 16px;
        border-radius: 0;
        border-left: 0;
        border-right: 0;
      }
    }
  </style>
</head>
<body>
  <main class="markdown-body">{{.BodyHTML}}</main>
  {{if .HasMermaid}}
  <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
  <script>if (window.mermaid) { window.mermaid.initialize({ startOnLoad: true, securityLevel: "loose" }); }</script>
  {{end}}
</body>
</html>`))

func buildMarkdownHTMLPage(data markdownPageData) ([]byte, error) {
	var out bytes.Buffer
	if err := markdownPageTemplate.Execute(&out, data); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func renderMarkdownDocument(src string) (string, string, bool) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	var out strings.Builder
	var paragraph []string
	var quote []string
	var codeFence []string
	var listItems []string
	var pageTitle string
	listType := ""
	codeLang := ""
	hasMermaid := false
	inCodeFence := false

	flushParagraph := func() {
		if len(paragraph) == 0 {
			return
		}
		text := strings.Join(paragraph, " ")
		out.WriteString("<p>")
		out.WriteString(renderMarkdownInline(strings.TrimSpace(text)))
		out.WriteString("</p>\n")
		paragraph = nil
	}
	flushList := func() {
		if len(listItems) == 0 {
			return
		}
		tag := "ul"
		if listType == "ol" {
			tag = "ol"
		}
		out.WriteString("<" + tag + ">\n")
		for _, item := range listItems {
			out.WriteString("<li>")
			out.WriteString(renderMarkdownInline(item))
			out.WriteString("</li>\n")
		}
		out.WriteString("</" + tag + ">\n")
		listItems = nil
		listType = ""
	}
	flushTable := func(headers []string, rows [][]string) {
		if len(headers) == 0 {
			return
		}
		out.WriteString("<table>\n<thead>\n<tr>")
		for _, cell := range headers {
			out.WriteString("<th>")
			out.WriteString(renderMarkdownInline(cell))
			out.WriteString("</th>")
		}
		out.WriteString("</tr>\n</thead>\n")
		if len(rows) > 0 {
			out.WriteString("<tbody>\n")
			for _, row := range rows {
				out.WriteString("<tr>")
				for _, cell := range row {
					out.WriteString("<td>")
					out.WriteString(renderMarkdownInline(cell))
					out.WriteString("</td>")
				}
				out.WriteString("</tr>\n")
			}
			out.WriteString("</tbody>\n")
		}
		out.WriteString("</table>\n")
	}
	flushQuote := func() {
		if len(quote) == 0 {
			return
		}
		text := strings.Join(quote, " ")
		out.WriteString("<blockquote><p>")
		out.WriteString(renderMarkdownInline(strings.TrimSpace(text)))
		out.WriteString("</p></blockquote>\n")
		quote = nil
	}
	flushCodeFence := func() {
		if !inCodeFence {
			return
		}
		code := strings.Join(codeFence, "\n")
		if strings.EqualFold(codeLang, "mermaid") {
			hasMermaid = true
			out.WriteString(`<pre class="mermaid">`)
			out.WriteString(html.EscapeString(code))
			out.WriteString("</pre>\n")
		} else {
			classAttr := ""
			dataLangAttr := ""
			if codeLang != "" {
				classAttr = ` class="language-` + html.EscapeString(codeLang) + `"`
				dataLangAttr = ` data-lang="` + html.EscapeString(codeLang) + `"`
			}
			out.WriteString("<pre><code" + classAttr + dataLangAttr + ">")
			out.WriteString(highlightCodeBlock(codeLang, code))
			out.WriteString("</code></pre>\n")
		}
		codeFence = nil
		codeLang = ""
		inCodeFence = false
	}

	for i := 0; i < len(lines); i++ {
		rawLine := lines[i]
		line := strings.TrimRight(rawLine, " \t")
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") {
			if inCodeFence {
				flushCodeFence()
			} else {
				flushParagraph()
				flushList()
				flushQuote()
				inCodeFence = true
				codeLang = strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
				codeFence = nil
			}
			continue
		}
		if inCodeFence {
			codeFence = append(codeFence, line)
			continue
		}
		if trimmed == "" {
			flushParagraph()
			flushList()
			flushQuote()
			continue
		}
		if level, text, ok := parseMarkdownHeading(trimmed); ok {
			flushParagraph()
			flushList()
			flushQuote()
			if level == 1 && pageTitle == "" {
				pageTitle = text
			}
			out.WriteString("<h")
			out.WriteString(strconv.Itoa(level))
			out.WriteString(">")
			out.WriteString(renderMarkdownInline(text))
			out.WriteString("</h")
			out.WriteString(strconv.Itoa(level))
			out.WriteString(">\n")
			continue
		}
		if trimmed == "---" || trimmed == "***" {
			flushParagraph()
			flushList()
			flushQuote()
			out.WriteString("<hr>\n")
			continue
		}
		if strings.HasPrefix(trimmed, ">") {
			flushParagraph()
			flushList()
			quote = append(quote, strings.TrimSpace(strings.TrimPrefix(trimmed, ">")))
			continue
		}
		flushQuote()
		if i+1 < len(lines) {
			headerCells, ok := parseMarkdownTableRow(trimmed)
			if ok && isMarkdownTableSeparator(strings.TrimSpace(lines[i+1])) {
				flushParagraph()
				flushList()
				var rows [][]string
				i += 2
				for ; i < len(lines); i++ {
					rowLine := strings.TrimSpace(lines[i])
					if rowLine == "" {
						i--
						break
					}
					rowCells, rowOK := parseMarkdownTableRow(rowLine)
					if !rowOK {
						i--
						break
					}
					rows = append(rows, padMarkdownTableRow(rowCells, len(headerCells)))
				}
				flushTable(headerCells, rows)
				continue
			}
		}
		if kind, item, ok := parseMarkdownListItem(trimmed); ok {
			flushParagraph()
			if listType != "" && listType != kind {
				flushList()
			}
			listType = kind
			listItems = append(listItems, item)
			continue
		}
		flushList()
		paragraph = append(paragraph, trimmed)
	}

	flushParagraph()
	flushList()
	flushQuote()
	flushCodeFence()

	if out.Len() == 0 {
		out.WriteString("<p></p>\n")
	}
	return out.String(), pageTitle, hasMermaid
}

func parseMarkdownHeading(line string) (int, string, bool) {
	level := 0
	for level < len(line) && level < 6 && line[level] == '#' {
		level++
	}
	if level == 0 || level >= len(line) || line[level] != ' ' {
		return 0, "", false
	}
	return level, strings.TrimSpace(line[level:]), true
}

var orderedListPattern = regexp.MustCompile(`^\d+\.\s+(.+)$`)

func parseMarkdownListItem(line string) (string, string, bool) {
	for _, prefix := range []string{"- ", "* ", "+ "} {
		if strings.HasPrefix(line, prefix) {
			return "ul", strings.TrimSpace(strings.TrimPrefix(line, prefix)), true
		}
	}
	if matches := orderedListPattern.FindStringSubmatch(line); len(matches) == 2 {
		return "ol", strings.TrimSpace(matches[1]), true
	}
	return "", "", false
}

func renderMarkdownInline(s string) string {
	s = html.EscapeString(strings.TrimSpace(s))
	s, codeSpans := extractInlineCodeSpans(s)
	s = renderMarkdownImages(s)
	s = renderMarkdownLinks(s)
	s = renderMarkdownDelimited(s, "**", "<strong>", "</strong>")
	s = renderMarkdownDelimited(s, "__", "<strong>", "</strong>")
	s = renderMarkdownDelimited(s, "*", "<em>", "</em>")
	s = renderMarkdownDelimited(s, "_", "<em>", "</em>")
	s = restoreInlineCodeSpans(s, codeSpans)
	return s
}

var markdownImagePattern = regexp.MustCompile(`!\[(.*?)\]\((.*?)\)`)
var markdownLinkPattern = regexp.MustCompile(`\[(.*?)\]\((.*?)\)`)

func renderMarkdownImages(s string) string {
	return markdownImagePattern.ReplaceAllStringFunc(s, func(match string) string {
		parts := markdownImagePattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		src := strings.TrimSpace(html.UnescapeString(parts[2]))
		if src == "" {
			return match
		}
		if u, err := url.Parse(src); err != nil || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "data") {
			return match
		}
		alt := html.EscapeString(html.UnescapeString(parts[1]))
		return `<img src="` + html.EscapeString(src) + `" alt="` + alt + `">`
	})
}

func renderMarkdownLinks(s string) string {
	return markdownLinkPattern.ReplaceAllStringFunc(s, func(match string) string {
		parts := markdownLinkPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		href := strings.TrimSpace(html.UnescapeString(parts[2]))
		if href == "" {
			return match
		}
		if u, err := url.Parse(href); err != nil || (u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "mailto") {
			return match
		}
		text := renderMarkdownInline(html.UnescapeString(parts[1]))
		return `<a href="` + html.EscapeString(href) + `">` + text + `</a>`
	})
}

func renderMarkdownDelimited(s, delim, openTag, closeTag string) string {
	if delim == "" {
		return s
	}
	var out strings.Builder
	for {
		start := strings.Index(s, delim)
		if start < 0 {
			out.WriteString(s)
			return out.String()
		}
		end := strings.Index(s[start+len(delim):], delim)
		if end < 0 {
			out.WriteString(s)
			return out.String()
		}
		end += start + len(delim)
		out.WriteString(s[:start])
		content := s[start+len(delim) : end]
		if strings.TrimSpace(content) == "" {
			out.WriteString(s[:end+len(delim)])
			s = s[end+len(delim):]
			continue
		}
		out.WriteString(openTag)
		out.WriteString(content)
		out.WriteString(closeTag)
		s = s[end+len(delim):]
	}
}

func extractInlineCodeSpans(s string) (string, []string) {
	var spans []string
	var out strings.Builder
	for {
		start := strings.Index(s, "`")
		if start < 0 {
			out.WriteString(s)
			break
		}
		end := strings.Index(s[start+1:], "`")
		if end < 0 {
			out.WriteString(s)
			break
		}
		end += start + 1
		out.WriteString(s[:start])
		content := s[start+1 : end]
		token := fmt.Sprintf("%%CODE%d%%", len(spans))
		spans = append(spans, "<code>"+content+"</code>")
		out.WriteString(token)
		s = s[end+1:]
	}
	return out.String(), spans
}

func restoreInlineCodeSpans(s string, spans []string) string {
	for i, span := range spans {
		token := fmt.Sprintf("%%CODE%d%%", i)
		s = strings.ReplaceAll(s, token, span)
	}
	return s
}

func parseMarkdownTableRow(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.Contains(line, "|") {
		return nil, false
	}
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	if len(parts) < 2 {
		return nil, false
	}
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cells = append(cells, strings.TrimSpace(part))
	}
	return cells, true
}

func isMarkdownTableSeparator(line string) bool {
	cells, ok := parseMarkdownTableRow(line)
	if !ok {
		return false
	}
	for _, cell := range cells {
		if cell == "" {
			return false
		}
		for _, r := range cell {
			if r != '-' && r != ':' && r != ' ' {
				return false
			}
		}
	}
	return true
}

func padMarkdownTableRow(row []string, width int) []string {
	if len(row) >= width {
		return row[:width]
	}
	out := make([]string, width)
	copy(out, row)
	return out
}

func highlightCodeBlock(lang, code string) string {
	normalized := normalizeCodeLanguage(lang)
	switch normalized {
	case "go":
		return highlightCodeLike(code, codeHighlightSpec{
			keywords:     []string{"break", "case", "chan", "const", "continue", "default", "defer", "else", "fallthrough", "for", "func", "go", "goto", "if", "import", "interface", "map", "package", "range", "return", "select", "struct", "switch", "type", "var"},
			types:        []string{"any", "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr"},
			lineComment:  "//",
			blockComment: true,
			singleQuote:  true,
			doubleQuote:  true,
			backtick:     true,
		})
	case "js", "ts":
		return highlightCodeLike(code, codeHighlightSpec{
			keywords:     []string{"async", "await", "break", "case", "catch", "class", "const", "continue", "default", "delete", "else", "export", "extends", "finally", "for", "from", "function", "if", "import", "in", "instanceof", "let", "new", "of", "return", "static", "super", "switch", "this", "throw", "try", "typeof", "var", "while", "yield"},
			types:        []string{"boolean", "number", "string", "object", "undefined", "null", "void", "unknown", "never"},
			lineComment:  "//",
			blockComment: true,
			singleQuote:  true,
			doubleQuote:  true,
			backtick:     true,
		})
	case "json":
		return highlightJSON(code)
	case "yaml":
		return highlightYAML(code)
	case "sh", "bash", "zsh", "shell":
		return highlightShell(code)
	case "html", "xml":
		return highlightMarkup(code)
	case "css":
		return highlightCSS(code)
	default:
		return html.EscapeString(code)
	}
}

func normalizeCodeLanguage(lang string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	switch lang {
	case "golang":
		return "go"
	case "javascript":
		return "js"
	case "typescript":
		return "ts"
	case "yml":
		return "yaml"
	case "shellscript", "console":
		return "sh"
	default:
		return lang
	}
}

type codeHighlightSpec struct {
	keywords     []string
	types        []string
	lineComment  string
	blockComment bool
	singleQuote  bool
	doubleQuote  bool
	backtick     bool
}

func highlightCodeLike(code string, spec codeHighlightSpec) string {
	keywordSet := make(map[string]struct{}, len(spec.keywords))
	for _, v := range spec.keywords {
		keywordSet[v] = struct{}{}
	}
	typeSet := make(map[string]struct{}, len(spec.types))
	for _, v := range spec.types {
		typeSet[v] = struct{}{}
	}
	var out strings.Builder
	for i := 0; i < len(code); {
		if spec.lineComment != "" && strings.HasPrefix(code[i:], spec.lineComment) {
			j := i + len(spec.lineComment)
			for j < len(code) && code[j] != '\n' {
				j++
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if spec.blockComment && strings.HasPrefix(code[i:], "/*") {
			j := i + 2
			for j+1 < len(code) && code[j:j+2] != "*/" {
				j++
			}
			if j+1 < len(code) {
				j += 2
			} else {
				j = len(code)
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if (spec.singleQuote && code[i] == '\'') || (spec.doubleQuote && code[i] == '"') || (spec.backtick && code[i] == '`') {
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if quote != '`' && code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == quote {
					j++
					break
				}
				j++
			}
			writeToken(&out, "tok-string", code[i:j])
			i = j
			continue
		}
		if isCodeNumberStart(code, i) {
			j := i + 1
			for j < len(code) && isCodeNumberPart(code[j]) {
				j++
			}
			writeToken(&out, "tok-number", code[i:j])
			i = j
			continue
		}
		if isCodeIdentStart(code[i]) {
			j := i + 1
			for j < len(code) && isCodeIdentPart(code[j]) {
				j++
			}
			word := code[i:j]
			if _, ok := keywordSet[word]; ok {
				writeToken(&out, "tok-keyword", word)
			} else if _, ok := typeSet[word]; ok {
				writeToken(&out, "tok-type", word)
			} else if nextNonSpaceByte(code, j) == '(' {
				writeToken(&out, "tok-func", word)
			} else {
				out.WriteString(html.EscapeString(word))
			}
			i = j
			continue
		}
		if strings.ContainsRune("{}[]():.,;", rune(code[i])) {
			writeToken(&out, "tok-punct", code[i:i+1])
		} else {
			out.WriteString(html.EscapeString(code[i : i+1]))
		}
		i++
	}
	return out.String()
}

func highlightShell(code string) string {
	keywords := map[string]struct{}{
		"if": {}, "then": {}, "else": {}, "elif": {}, "fi": {}, "for": {}, "in": {}, "do": {}, "done": {},
		"case": {}, "esac": {}, "while": {}, "until": {}, "function": {}, "select": {}, "time": {}, "coproc": {},
	}
	builtins := map[string]struct{}{
		"cd": {}, "echo": {}, "exit": {}, "export": {}, "local": {}, "readonly": {}, "return": {}, "set": {}, "shift": {}, "source": {}, "unset": {},
	}
	var out strings.Builder
	for i := 0; i < len(code); {
		if code[i] == '#' {
			j := i + 1
			for j < len(code) && code[j] != '\n' {
				j++
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if code[i] == '\'' || code[i] == '"' {
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if quote == '"' && code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == quote {
					j++
					break
				}
				j++
			}
			writeToken(&out, "tok-string", code[i:j])
			i = j
			continue
		}
		if code[i] == '$' {
			j := i + 1
			if j < len(code) && code[j] == '{' {
				j++
				for j < len(code) && code[j] != '}' {
					j++
				}
				if j < len(code) {
					j++
				}
			} else {
				for j < len(code) && (isCodeIdentPart(code[j]) || code[j] == '@' || code[j] == '*' || code[j] == '#') {
					j++
				}
			}
			writeToken(&out, "tok-var", code[i:j])
			i = j
			continue
		}
		if isCodeIdentStart(code[i]) {
			j := i + 1
			for j < len(code) && isCodeIdentPart(code[j]) {
				j++
			}
			word := code[i:j]
			if _, ok := keywords[word]; ok {
				writeToken(&out, "tok-keyword", word)
			} else if _, ok := builtins[word]; ok {
				writeToken(&out, "tok-func", word)
			} else {
				out.WriteString(html.EscapeString(word))
			}
			i = j
			continue
		}
		out.WriteString(html.EscapeString(code[i : i+1]))
		i++
	}
	return out.String()
}

func highlightJSON(code string) string {
	var out strings.Builder
	for i := 0; i < len(code); {
		if code[i] == '"' {
			j := i + 1
			for j < len(code) {
				if code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == '"' {
					j++
					break
				}
				j++
			}
			token := code[i:j]
			className := "tok-string"
			if nextNonSpaceByte(code, j) == ':' {
				className = "tok-attr"
			}
			writeToken(&out, className, token)
			i = j
			continue
		}
		if isCodeNumberStart(code, i) {
			j := i + 1
			for j < len(code) && isCodeNumberPart(code[j]) {
				j++
			}
			writeToken(&out, "tok-number", code[i:j])
			i = j
			continue
		}
		for _, literal := range []string{"true", "false", "null"} {
			if strings.HasPrefix(code[i:], literal) && !isCodeIdentBoundary(code, i-1) && !isCodeIdentBoundary(code, i+len(literal)) {
				writeToken(&out, "tok-keyword", literal)
				i += len(literal)
				goto nextJSON
			}
		}
		if strings.ContainsRune("{}[]:,", rune(code[i])) {
			writeToken(&out, "tok-punct", code[i:i+1])
		} else {
			out.WriteString(html.EscapeString(code[i : i+1]))
		}
		i++
	nextJSON:
	}
	return out.String()
}

func highlightYAML(code string) string {
	lines := strings.SplitAfter(code, "\n")
	var out strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		indentLen := len(line) - len(trimmed)
		out.WriteString(html.EscapeString(line[:indentLen]))
		if strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			writeToken(&out, "tok-comment", strings.TrimRight(trimmed, "\n"))
			if strings.HasSuffix(line, "\n") {
				out.WriteString("\n")
			}
			continue
		}
		if key, rest, ok := splitStaticYAMLKeyValue(strings.TrimRight(trimmed, "\n")); ok {
			writeToken(&out, "tok-attr", key)
			writeToken(&out, "tok-punct", ":")
			if rest != "" {
				out.WriteString(" ")
				out.WriteString(highlightYAMLScalar(rest))
			}
			if strings.HasSuffix(line, "\n") {
				out.WriteString("\n")
			}
			continue
		}
		out.WriteString(highlightYAMLScalar(strings.TrimRight(trimmed, "\n")))
		if strings.HasSuffix(line, "\n") {
			out.WriteString("\n")
		}
	}
	return out.String()
}

func splitStaticYAMLKeyValue(line string) (string, string, bool) {
	if line == "" || strings.HasPrefix(line, "- ") {
		return "", "", false
	}
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	return line[:idx], strings.TrimSpace(line[idx+1:]), true
}

func highlightYAMLScalar(s string) string {
	switch s {
	case "true", "false", "null", "~":
		return wrapToken("tok-keyword", s)
	}
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return wrapToken("tok-string", s)
	}
	if len(s) > 0 && isCodeNumberStart(s, 0) {
		allNum := true
		for i := 1; i < len(s); i++ {
			if !isCodeNumberPart(s[i]) {
				allNum = false
				break
			}
		}
		if allNum {
			return wrapToken("tok-number", s)
		}
	}
	return html.EscapeString(s)
}

func highlightMarkup(code string) string {
	escaped := html.EscapeString(code)
	escaped = regexp.MustCompile(`&lt;!--[\s\S]*?--&gt;`).ReplaceAllStringFunc(escaped, func(m string) string {
		return wrapToken("tok-comment", html.UnescapeString(m))
	})
	escaped = regexp.MustCompile(`&lt;/?[A-Za-z0-9:_-]+`).ReplaceAllStringFunc(escaped, func(m string) string {
		return wrapToken("tok-tag", html.UnescapeString(m))
	})
	escaped = regexp.MustCompile(`\s([A-Za-z_:][-A-Za-z0-9_:.]*)(=)`).ReplaceAllString(escaped, ` <span class="tok-attr">$1</span><span class="tok-punct">$2</span>`)
	escaped = regexp.MustCompile(`"[^"]*"`).ReplaceAllStringFunc(escaped, func(m string) string {
		return wrapToken("tok-string", html.UnescapeString(m))
	})
	escaped = strings.ReplaceAll(escaped, "&gt;", wrapToken("tok-tag", ">"))
	return escaped
}

func highlightCSS(code string) string {
	var out strings.Builder
	for i := 0; i < len(code); {
		if strings.HasPrefix(code[i:], "/*") {
			j := i + 2
			for j+1 < len(code) && code[j:j+2] != "*/" {
				j++
			}
			if j+1 < len(code) {
				j += 2
			} else {
				j = len(code)
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if code[i] == '"' || code[i] == '\'' {
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == quote {
					j++
					break
				}
				j++
			}
			writeToken(&out, "tok-string", code[i:j])
			i = j
			continue
		}
		if isCodeIdentStart(code[i]) || code[i] == '.' || code[i] == '#' {
			j := i + 1
			for j < len(code) && (isCodeIdentPart(code[j]) || strings.ContainsRune(".#-%", rune(code[j]))) {
				j++
			}
			word := code[i:j]
			next := nextNonSpaceByte(code, j)
			className := ""
			switch next {
			case ':':
				className = "tok-attr"
			case '{':
				className = "tok-tag"
			}
			if className != "" {
				writeToken(&out, className, word)
			} else {
				out.WriteString(html.EscapeString(word))
			}
			i = j
			continue
		}
		if isCodeNumberStart(code, i) {
			j := i + 1
			for j < len(code) && (isCodeNumberPart(code[j]) || unicode.IsLetter(rune(code[j])) || code[j] == '%') {
				j++
			}
			writeToken(&out, "tok-number", code[i:j])
			i = j
			continue
		}
		out.WriteString(html.EscapeString(code[i : i+1]))
		i++
	}
	return out.String()
}

func writeToken(out *strings.Builder, className, text string) {
	out.WriteString(wrapToken(className, text))
}

func wrapToken(className, text string) string {
	return `<span class="` + className + `">` + html.EscapeString(text) + `</span>`
}

func isCodeIdentStart(b byte) bool {
	return b == '_' || unicode.IsLetter(rune(b))
}

func isCodeIdentPart(b byte) bool {
	return isCodeIdentStart(b) || (b >= '0' && b <= '9')
}

func isCodeNumberStart(s string, i int) bool {
	if i < 0 || i >= len(s) || s[i] < '0' || s[i] > '9' {
		return false
	}
	return i == 0 || !isCodeIdentPart(s[i-1])
}

func isCodeNumberPart(b byte) bool {
	return (b >= '0' && b <= '9') || b == '.' || b == '_' || b == 'x' || b == 'X' || b == 'a' || b == 'b' || b == 'c' || b == 'd' || b == 'e' || b == 'E' || b == 'f' || b == 'F' || b == '+' || b == '-'
}

func nextNonSpaceByte(s string, i int) byte {
	for i < len(s) {
		if !unicode.IsSpace(rune(s[i])) {
			return s[i]
		}
		i++
	}
	return 0
}

func isCodeIdentBoundary(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return true
	}
	return !isCodeIdentPart(s[i])
}

type staticFileSystem struct {
	root   http.FileSystem
	policy staticAccessPolicy
}

func (fsys staticFileSystem) Open(name string) (http.File, error) {
	cleanName := staticCleanPath(name)
	rel := strings.TrimPrefix(cleanName, "/")
	f, err := fsys.root.Open(cleanName)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if rel != "" && fsys.policy.Blocked(rel, info.IsDir()) {
		_ = f.Close()
		return nil, fs.ErrNotExist
	}
	if !info.IsDir() {
		return f, nil
	}
	return &staticDir{
		File:   f,
		rel:    rel,
		policy: fsys.policy,
	}, nil
}

type staticDir struct {
	http.File
	rel     string
	policy  staticAccessPolicy
	loaded  bool
	entries []os.FileInfo
	next    int
}

func (d *staticDir) Readdir(count int) ([]os.FileInfo, error) {
	if !d.loaded {
		entries, err := d.File.Readdir(-1)
		if err != nil {
			return nil, err
		}
		filtered := make([]os.FileInfo, 0, len(entries))
		for _, entry := range entries {
			childRel := entry.Name()
			if d.rel != "" {
				childRel = path.Join(d.rel, entry.Name())
			}
			if d.policy.Blocked(childRel, entry.IsDir()) {
				continue
			}
			filtered = append(filtered, entry)
		}
		d.entries = filtered
		d.loaded = true
	}

	if count <= 0 {
		remaining := d.entries[d.next:]
		d.next = len(d.entries)
		return remaining, nil
	}
	if d.next >= len(d.entries) {
		return nil, io.EOF
	}
	end := d.next + count
	if end > len(d.entries) {
		end = len(d.entries)
	}
	out := d.entries[d.next:end]
	d.next = end
	return out, nil
}

type staticAccessPolicy struct {
	allow                 []staticAllowPattern
	restrictPublicFileExt bool
}

func newStaticAccessPolicy(unprotected bool, patterns []string) (staticAccessPolicy, error) {
	policy := staticAccessPolicy{restrictPublicFileExt: unprotected}
	for _, raw := range patterns {
		pattern, err := parseStaticAllowPattern(raw)
		if err != nil {
			return staticAccessPolicy{}, err
		}
		policy.allow = append(policy.allow, pattern)
	}
	return policy, nil
}

func (p staticAccessPolicy) Blocked(rel string, isDir bool) bool {
	rel = normalizeStaticRelPath(rel)
	if rel == "" {
		return false
	}
	if p.Allowed(rel) {
		return false
	}
	segments := strings.Split(rel, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return true
		}
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}
	if !isDir {
		name := segments[len(segments)-1]
		for _, suffix := range []string{"~", ".bak", ".backup", ".old", ".orig", ".swp", ".tmp"} {
			if strings.HasSuffix(strings.ToLower(name), suffix) {
				return true
			}
		}
		if p.restrictPublicFileExt && !isAllowedPublicStaticAsset(name) {
			return true
		}
	}
	return false
}

func (p staticAccessPolicy) Allowed(rel string) bool {
	rel = normalizeStaticRelPath(rel)
	if rel == "" {
		return false
	}
	target := strings.Split(rel, "/")
	for _, pattern := range p.allow {
		if pattern.match(target) {
			return true
		}
	}
	return false
}

type staticAllowPattern struct {
	segments []string
}

func parseStaticAllowPattern(raw string) (staticAllowPattern, error) {
	raw = normalizeStaticRelPath(raw)
	if raw == "" {
		return staticAllowPattern{}, errors.New("allow pattern cannot be empty")
	}
	segments := strings.Split(raw, "/")
	for _, segment := range segments {
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, ""); err != nil {
			return staticAllowPattern{}, err
		}
	}
	return staticAllowPattern{
		segments: segments,
	}, nil
}

func (p staticAllowPattern) match(target []string) bool {
	return matchStaticPatternSegments(p.segments, target)
}

func matchStaticPatternSegments(pattern, target []string) bool {
	if len(pattern) == 0 {
		return len(target) == 0
	}
	if pattern[0] == "**" {
		if len(pattern) == 1 {
			return true
		}
		for i := 0; i <= len(target); i++ {
			if matchStaticPatternSegments(pattern[1:], target[i:]) {
				return true
			}
		}
		return false
	}
	if len(target) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], target[0])
	if err != nil || !ok {
		return false
	}
	return matchStaticPatternSegments(pattern[1:], target[1:])
}

func staticCleanPath(name string) string {
	name = strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if name == "" {
		return "/"
	}
	clean := path.Clean("/" + strings.TrimPrefix(name, "/"))
	if clean == "." {
		return "/"
	}
	return clean
}

func normalizeStaticRelPath(name string) string {
	clean := staticCleanPath(name)
	if clean == "/" {
		return ""
	}
	return strings.TrimPrefix(clean, "/")
}

func defaultStaticSubdomain(machineID, root string) string {
	machineID = strings.ToLower(strings.TrimSpace(machineID))
	root = strings.TrimSpace(root)
	if machineID == "" || root == "" {
		return ""
	}
	sum := sha1.Sum([]byte(machineID + ":" + root))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	enc = strings.ToLower(enc)
	const subdomainLen = 6
	if len(enc) > subdomainLen {
		enc = enc[:subdomainLen]
	}
	return enc
}

func isAllowedPublicStaticAsset(name string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(name)))
	if ext == "" {
		return false
	}
	_, ok := allowedPublicStaticAssetExt[ext]
	return ok
}

var allowedPublicStaticAssetExt = map[string]struct{}{
	".avif":        {},
	".bmp":         {},
	".css":         {},
	".csv":         {},
	".doc":         {},
	".docx":        {},
	".eot":         {},
	".gif":         {},
	".gz":          {},
	".htm":         {},
	".html":        {},
	".ico":         {},
	".jpeg":        {},
	".jpg":         {},
	".js":          {},
	".json":        {},
	".m4a":         {},
	".map":         {},
	".markdown":    {},
	".md":          {},
	".mjs":         {},
	".mp3":         {},
	".mp4":         {},
	".odp":         {},
	".ods":         {},
	".odt":         {},
	".ogv":         {},
	".ogg":         {},
	".pdf":         {},
	".png":         {},
	".ppt":         {},
	".pptx":        {},
	".rtf":         {},
	".svg":         {},
	".tar":         {},
	".tgz":         {},
	".ts":          {},
	".tsv":         {},
	".ttf":         {},
	".txt":         {},
	".wasm":        {},
	".wav":         {},
	".webm":        {},
	".webmanifest": {},
	".webp":        {},
	".woff":        {},
	".woff2":       {},
	".xls":         {},
	".xlsx":        {},
	".xml":         {},
	".zip":         {},
}
