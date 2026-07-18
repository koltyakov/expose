// Markdown page rendering for the static file server: converts .md files
// into styled HTML pages with sanitized raw-HTML support.
package cli

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
	xatom "golang.org/x/net/html/atom"
)

var staticMarkdownFaviconNames = []string{
	"favicon.svg",
	"favicon.png",
	"favicon.ico",
	"favicon.jpg",
	"favicon.jpeg",
	"favicon.webp",
	"apple-touch-icon.png",
}

func staticShouldRenderMarkdown(method, name string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(name)))
	return ext == ".md" || ext == ".markdown"
}

func (h *staticHandler) serveRenderedMarkdownFile(w http.ResponseWriter, r *http.Request, _ string, file http.File, info os.FileInfo, directoryDefault bool) bool {
	body, err := io.ReadAll(file)
	if err != nil {
		return false
	}
	internalPath := staticCleanPath(r.URL.Path)
	publicPath := staticPublicRequestPath(r, directoryDefault)
	rendered, title, hasMermaid := renderMarkdownDocument(string(body), publicPath)
	if strings.TrimSpace(title) == "" {
		title = strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
	}
	faviconHref := h.resolveMarkdownFaviconHref(internalPath, staticMountPrefix(r))
	page, err := buildMarkdownHTMLPage(markdownPageData{
		Title:           title,
		BodyHTML:        template.HTML(rendered),
		FaviconHref:     faviconHref,
		FaviconType:     staticFaviconContentType(faviconHref),
		UseShortcutIcon: staticShouldUseShortcutIcon(faviconHref),
		HasMermaid:      hasMermaid,
	})
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, info.Name()+".html", info.ModTime(), bytes.NewReader(page))
	return true
}

type markdownPageData struct {
	Title           string
	BodyHTML        template.HTML
	FaviconHref     string
	FaviconType     string
	UseShortcutIcon bool
	HasMermaid      bool
}

var markdownPageTemplate = template.Must(template.New("markdown-page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  {{if .FaviconHref}}<link rel="icon"{{if .FaviconType}} type="{{.FaviconType}}"{{end}} href="{{.FaviconHref}}">{{end}}
  {{if .UseShortcutIcon}}<link rel="shortcut icon" href="{{.FaviconHref}}">{{end}}
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

func (h *staticHandler) resolveMarkdownFaviconHref(internalRequestPath, mountPrefix string) string {
	for _, candidate := range staticMarkdownFaviconCandidates(internalRequestPath) {
		file, info, ok := h.open(candidate)
		if !ok {
			continue
		}
		_ = file.Close()
		if info != nil && !info.IsDir() {
			return staticMountPath(candidate, mountPrefix)
		}
	}
	return staticMountPath("/favicon.ico", mountPrefix)
}

func staticFaviconContentType(href string) string {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(href))) {
	case ".ico":
		return "image/x-icon"
	case ".png":
		return "image/png"
	case ".svg":
		return "image/svg+xml"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	default:
		return ""
	}
}

func staticShouldUseShortcutIcon(href string) bool {
	return strings.EqualFold(strings.TrimSpace(filepath.Ext(href)), ".ico")
}

func staticPublicRequestPath(r *http.Request, directoryDefault bool) string {
	publicPath := staticCleanPath(strings.TrimSpace(r.Header.Get(upRoutePublicPathHeader)))
	if publicPath == "/" && strings.TrimSpace(r.Header.Get(upRoutePublicPathHeader)) == "" {
		publicPath = staticCleanPath(r.URL.Path)
	}
	if directoryDefault {
		return staticDirectoryPath(publicPath)
	}
	return publicPath
}

func staticMountPrefix(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get(upRouteMountPrefixHeader))
}

func staticMountPath(p, mountPrefix string) string {
	p = staticCleanPath(p)
	mountPrefix = strings.TrimSpace(mountPrefix)
	if mountPrefix == "" || mountPrefix == "/" {
		return p
	}
	mountPrefix = staticCleanPath(mountPrefix)
	if p == "/" {
		return staticDirectoryPath(mountPrefix)
	}
	return strings.TrimSuffix(mountPrefix, "/") + p
}

func staticMarkdownFaviconCandidates(requestPath string) []string {
	cleanPath := staticCleanPath(requestPath)
	searchDir := cleanPath
	if !strings.HasSuffix(strings.TrimSpace(requestPath), "/") {
		searchDir = path.Dir(cleanPath)
	}
	if searchDir == "." || searchDir == "" {
		searchDir = "/"
	}

	seen := make(map[string]struct{}, len(staticMarkdownFaviconNames)*2)
	candidates := make([]string, 0, len(staticMarkdownFaviconNames)*2)
	for {
		for _, name := range staticMarkdownFaviconNames {
			candidate := path.Join(searchDir, name)
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			candidates = append(candidates, candidate)
		}
		if searchDir == "/" {
			break
		}
		searchDir = path.Dir(searchDir)
		if searchDir == "." || searchDir == "" {
			searchDir = "/"
		}
	}
	return candidates
}

func renderMarkdownDocument(src, requestPath string) (string, string, bool) {
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
		out.WriteString(renderMarkdownInline(strings.TrimSpace(text), requestPath))
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
			out.WriteString(renderMarkdownInline(item, requestPath))
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
			out.WriteString(renderMarkdownInline(cell, requestPath))
			out.WriteString("</th>")
		}
		out.WriteString("</tr>\n</thead>\n")
		if len(rows) > 0 {
			out.WriteString("<tbody>\n")
			for _, row := range rows {
				out.WriteString("<tr>")
				for _, cell := range row {
					out.WriteString("<td>")
					out.WriteString(renderMarkdownInline(cell, requestPath))
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
		out.WriteString(renderMarkdownInline(strings.TrimSpace(text), requestPath))
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

		if after, ok := strings.CutPrefix(trimmed, "```"); ok {
			if inCodeFence {
				flushCodeFence()
			} else {
				flushParagraph()
				flushList()
				flushQuote()
				inCodeFence = true
				codeLang = strings.TrimSpace(after)
				codeFence = nil
			}
			continue
		}
		if inCodeFence {
			codeFence = append(codeFence, line)
			continue
		}
		if renderedHTML, consumed, ok := renderAllowedMarkdownRawHTMLBlock(lines, i, requestPath); ok {
			flushParagraph()
			flushList()
			flushQuote()
			out.WriteString(renderedHTML)
			i += consumed - 1
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
			out.WriteString(renderMarkdownInline(text, requestPath))
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
var markdownImagePattern = regexp.MustCompile(`!\[(.*?)\]\((.*?)\)`)
var markdownLinkPattern = regexp.MustCompile(`\[(.*?)\]\((.*?)\)`)
var markdownImageDimensionPattern = regexp.MustCompile(`^[1-9]\d{0,3}$`)
var markdownAllowedRawHTMLTags = map[string]struct{}{
	"a": {}, "abbr": {}, "b": {}, "blockquote": {}, "br": {}, "code": {}, "del": {}, "details": {},
	"div": {}, "em": {}, "i": {}, "img": {}, "kbd": {}, "li": {}, "ol": {}, "p": {}, "pre": {},
	"s": {}, "small": {}, "span": {}, "strong": {}, "sub": {}, "summary": {}, "sup": {},
	"table": {}, "tbody": {}, "td": {}, "th": {}, "thead": {}, "tr": {}, "ul": {},
}
var markdownAllowedRawHTMLGlobalAttrs = map[string]struct{}{
	"align": {}, "title": {},
}
var markdownAllowedRawHTMLTagAttrs = map[string]map[string]struct{}{
	"a":       {"href": {}},
	"details": {"open": {}},
	"img":     {"src": {}, "alt": {}, "width": {}, "height": {}},
	"ol":      {"start": {}},
	"td":      {"colspan": {}, "rowspan": {}, "align": {}},
	"th":      {"colspan": {}, "rowspan": {}, "align": {}},
}
var markdownAllowedAlignValues = map[string]struct{}{
	"left": {}, "center": {}, "right": {}, "justify": {},
}
var markdownRawHTMLVoidTags = map[string]struct{}{
	"area": {}, "base": {}, "br": {}, "col": {}, "embed": {}, "hr": {}, "img": {}, "input": {},
	"link": {}, "meta": {}, "param": {}, "source": {}, "track": {}, "wbr": {},
}

func parseMarkdownListItem(line string) (string, string, bool) {
	for _, prefix := range []string{"- ", "* ", "+ "} {
		if after, ok := strings.CutPrefix(line, prefix); ok {
			return "ul", strings.TrimSpace(after), true
		}
	}
	if matches := orderedListPattern.FindStringSubmatch(line); len(matches) == 2 {
		return "ol", strings.TrimSpace(matches[1]), true
	}
	return "", "", false
}

func renderAllowedMarkdownRawHTMLBlock(lines []string, start int, requestPath string) (string, int, bool) {
	if start < 0 || start >= len(lines) {
		return "", 0, false
	}

	firstLine := strings.TrimSpace(strings.TrimRight(lines[start], " \t"))
	if firstLine == "" || !markdownLooksLikeRawHTMLStart(firstLine) {
		return "", 0, false
	}

	var blockLines []string
	for end := start; end < len(lines); end++ {
		blockLines = append(blockLines, strings.TrimRight(lines[end], " \t"))
		candidate := strings.TrimSpace(strings.Join(blockLines, "\n"))
		if candidate == "" || !markdownRawHTMLFragmentComplete(candidate) {
			continue
		}
		rendered, ok := sanitizeMarkdownRawHTMLFragment(candidate, requestPath)
		if !ok {
			return "", 0, false
		}
		return rendered + "\n", end - start + 1, true
	}

	return "", 0, false
}

func sanitizeMarkdownRawHTMLFragment(fragment, requestPath string) (string, bool) {
	fragment = strings.TrimSpace(fragment)
	if fragment == "" || !strings.HasPrefix(fragment, "<") || !strings.HasSuffix(fragment, ">") {
		return "", false
	}

	nodes, err := xhtml.ParseFragment(strings.NewReader(fragment), &xhtml.Node{Type: xhtml.ElementNode, Data: "div", DataAtom: xatom.Div})
	if err != nil || len(nodes) == 0 {
		return "", false
	}

	var out strings.Builder
	hasElement := false
	for _, n := range nodes {
		clean, ok := sanitizeMarkdownRawHTMLNode(n, requestPath)
		if !ok {
			return "", false
		}
		if clean == nil {
			continue
		}
		if clean.Type == xhtml.ElementNode {
			hasElement = true
		}
		if err := xhtml.Render(&out, clean); err != nil {
			return "", false
		}
	}
	if !hasElement {
		return "", false
	}
	return out.String(), true
}

func markdownRawHTMLFragmentComplete(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || !markdownLooksLikeRawHTMLStart(raw) || !strings.HasSuffix(raw, ">") {
		return false
	}

	tokenizer := xhtml.NewTokenizer(strings.NewReader(raw))
	stack := make([]string, 0, 8)
	hasElement := false

	for {
		switch tokenizer.Next() {
		case xhtml.ErrorToken:
			return errors.Is(tokenizer.Err(), io.EOF) && hasElement && len(stack) == 0
		case xhtml.StartTagToken:
			token := tokenizer.Token()
			tag := strings.ToLower(strings.TrimSpace(token.Data))
			if tag == "" {
				continue
			}
			hasElement = true
			if _, ok := markdownRawHTMLVoidTags[tag]; ok {
				continue
			}
			stack = append(stack, tag)
		case xhtml.SelfClosingTagToken:
			token := tokenizer.Token()
			if strings.TrimSpace(token.Data) != "" {
				hasElement = true
			}
		case xhtml.EndTagToken:
			token := tokenizer.Token()
			tag := strings.ToLower(strings.TrimSpace(token.Data))
			if tag == "" {
				continue
			}
			hasElement = true
			if _, ok := markdownRawHTMLVoidTags[tag]; ok {
				continue
			}
			if len(stack) == 0 || stack[len(stack)-1] != tag {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}
}

func markdownLooksLikeRawHTMLStart(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '<' {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s[1:])
	return unicode.IsLetter(r) || r == '/' || r == '!' || r == '?'
}

func sanitizeMarkdownRawHTMLNode(n *xhtml.Node, requestPath string) (*xhtml.Node, bool) {
	if n == nil {
		return nil, true
	}
	switch n.Type {
	case xhtml.TextNode:
		return &xhtml.Node{Type: xhtml.TextNode, Data: n.Data}, true
	case xhtml.CommentNode:
		return nil, true
	case xhtml.ElementNode:
		tag := strings.ToLower(strings.TrimSpace(n.Data))
		if _, ok := markdownAllowedRawHTMLTags[tag]; !ok {
			return nil, false
		}
		attrs, ok := sanitizeMarkdownRawHTMLAttrs(tag, n.Attr, requestPath)
		if !ok {
			return nil, false
		}
		clean := &xhtml.Node{Type: xhtml.ElementNode, Data: tag, Attr: attrs}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			cleanChild, ok := sanitizeMarkdownRawHTMLNode(child, requestPath)
			if !ok {
				return nil, false
			}
			if cleanChild != nil {
				clean.AppendChild(cleanChild)
			}
		}
		return clean, true
	default:
		return nil, true
	}
}

func sanitizeMarkdownRawHTMLAttrs(tag string, attrs []xhtml.Attribute, requestPath string) ([]xhtml.Attribute, bool) {
	if len(attrs) == 0 {
		return nil, true
	}

	allowedTagAttrs := markdownAllowedRawHTMLTagAttrs[tag]
	seen := make(map[string]struct{}, len(attrs))
	out := make([]xhtml.Attribute, 0, len(attrs))
	for _, attr := range attrs {
		if attr.Namespace != "" {
			return nil, false
		}
		key := strings.ToLower(strings.TrimSpace(attr.Key))
		if key == "" {
			return nil, false
		}
		if _, dup := seen[key]; dup {
			continue
		}
		if _, ok := markdownAllowedRawHTMLGlobalAttrs[key]; !ok {
			if _, ok := allowedTagAttrs[key]; !ok {
				return nil, false
			}
		}

		value := strings.TrimSpace(attr.Val)
		switch key {
		case "href", "src":
			v, ok := sanitizeMarkdownRawHTMLURLAttr(key, value, requestPath)
			if !ok {
				return nil, false
			}
			value = v
		case "width", "height", "colspan", "rowspan", "start":
			if !markdownImageDimensionPattern.MatchString(value) {
				return nil, false
			}
		case "align":
			value = strings.ToLower(value)
			if _, ok := markdownAllowedAlignValues[value]; !ok {
				return nil, false
			}
		case "open":
			if tag != "details" {
				return nil, false
			}
			if value != "" && !strings.EqualFold(value, "open") {
				return nil, false
			}
			value = ""
		}

		out = append(out, xhtml.Attribute{Key: key, Val: value})
		seen[key] = struct{}{}
	}
	return out, true
}

func sanitizeMarkdownRawHTMLURLAttr(key, raw, requestPath string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "", false
	}
	if u.Scheme != "" {
		scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
		switch scheme {
		case "http", "https":
			return raw, true
		case "mailto":
			if key == "href" {
				return raw, true
			}
			return "", false
		case "data":
			if key == "src" {
				return raw, true
			}
			return "", false
		default:
			return "", false
		}
	}
	return resolveMarkdownURL(requestPath, raw), true
}

func renderMarkdownInline(s, requestPath string) string {
	s = html.EscapeString(strings.TrimSpace(s))
	s, codeSpans := extractInlineCodeSpans(s)
	s, rawHTMLSpans := extractInlineRawHTMLSpans(s, requestPath)
	s = renderMarkdownImages(s, requestPath)
	s = renderMarkdownLinks(s, requestPath)
	s = renderMarkdownDelimited(s, "**", "<strong>", "</strong>")
	s = renderMarkdownDelimited(s, "__", "<strong>", "</strong>")
	s = renderMarkdownDelimited(s, "*", "<em>", "</em>")
	s = renderMarkdownDelimited(s, "_", "<em>", "</em>")
	s = restoreInlineRawHTMLSpans(s, rawHTMLSpans)
	s = restoreInlineCodeSpans(s, codeSpans)
	return s
}

func extractInlineRawHTMLSpans(s, requestPath string) (string, []string) {
	var spans []string
	var out strings.Builder

	cursor := 0
	for cursor < len(s) {
		startRel := strings.Index(s[cursor:], "&lt;")
		if startRel < 0 {
			out.WriteString(s[cursor:])
			break
		}
		start := cursor + startRel
		out.WriteString(s[cursor:start])

		bestEnd := -1
		bestHTML := ""
		searchFrom := start
		for searchFrom < len(s) {
			endRel := strings.Index(s[searchFrom:], "&gt;")
			if endRel < 0 {
				break
			}
			end := searchFrom + endRel + len("&gt;")
			candidateRaw := html.UnescapeString(s[start:end])
			if strings.Contains(candidateRaw, "\n") || strings.Contains(candidateRaw, "\r") {
				break
			}
			if markdownRawHTMLFragmentComplete(candidateRaw) {
				clean, ok := sanitizeMarkdownRawHTMLFragment(candidateRaw, requestPath)
				if ok {
					bestEnd = end
					bestHTML = clean
				}
			}
			searchFrom = end
		}

		if bestEnd > start {
			token := fmt.Sprintf("%%RAWHTML%d%%", len(spans))
			spans = append(spans, bestHTML)
			out.WriteString(token)
			cursor = bestEnd
			continue
		}

		out.WriteString("&lt;")
		cursor = start + len("&lt;")
	}

	return out.String(), spans
}

func restoreInlineRawHTMLSpans(s string, spans []string) string {
	for i, span := range spans {
		token := fmt.Sprintf("%%RAWHTML%d%%", i)
		s = strings.ReplaceAll(s, token, span)
	}
	return s
}

func renderMarkdownImages(s, requestPath string) string {
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
		src = resolveMarkdownURL(requestPath, src)
		alt := html.EscapeString(html.UnescapeString(parts[1]))
		return `<img src="` + html.EscapeString(src) + `" alt="` + alt + `">`
	})
}

func renderMarkdownLinks(s, requestPath string) string {
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
		href = resolveMarkdownURL(requestPath, href)
		text := renderMarkdownInline(html.UnescapeString(parts[1]), requestPath)
		return `<a href="` + html.EscapeString(href) + `">` + text + `</a>`
	})
}

func resolveMarkdownURL(requestPath, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "?") || strings.HasPrefix(raw, "//") {
		return raw
	}

	ref, err := url.Parse(raw)
	if err != nil || ref == nil {
		return raw
	}
	if ref.Scheme != "" {
		return raw
	}

	basePath := strings.TrimSpace(requestPath)
	if basePath == "" {
		return raw
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	base := &url.URL{Path: basePath}
	resolved := base.ResolveReference(ref)
	if resolved == nil {
		return raw
	}

	out := resolved.EscapedPath()
	if out == "" {
		out = resolved.Path
	}
	if out == "" {
		out = "/"
	}
	if resolved.RawQuery != "" {
		out += "?" + resolved.RawQuery
	}
	if resolved.Fragment != "" {
		out += "#" + resolved.Fragment
	}
	return out
}

func renderMarkdownDelimited(s, delim, openTag, closeTag string) string {
	if delim == "" {
		return s
	}
	var out strings.Builder
	cursor := 0
	for {
		start := strings.Index(s[cursor:], delim)
		if start < 0 {
			out.WriteString(s[cursor:])
			return out.String()
		}
		start += cursor
		if !markdownDelimiterCanOpen(s, start, delim) {
			out.WriteString(s[cursor : start+len(delim)])
			cursor = start + len(delim)
			continue
		}

		end := -1
		searchFrom := start + len(delim)
		for {
			next := strings.Index(s[searchFrom:], delim)
			if next < 0 {
				out.WriteString(s[cursor:])
				return out.String()
			}
			next += searchFrom
			if markdownDelimiterCanClose(s, next, delim) {
				end = next
				break
			}
			searchFrom = next + len(delim)
		}

		out.WriteString(s[cursor:start])
		content := s[start+len(delim) : end]
		if strings.TrimSpace(content) == "" {
			out.WriteString(s[start : end+len(delim)])
			cursor = end + len(delim)
			continue
		}
		out.WriteString(openTag)
		out.WriteString(content)
		out.WriteString(closeTag)
		cursor = end + len(delim)
	}
}

func markdownDelimiterCanOpen(s string, idx int, delim string) bool {
	if !strings.Contains(delim, "_") {
		return true
	}
	prev, hasPrev := markdownPrevRune(s, idx)
	next, hasNext := markdownNextRune(s, idx+len(delim))
	if !hasNext || unicode.IsSpace(next) {
		return false
	}
	return !hasPrev || !isMarkdownWordRune(prev) || !isMarkdownWordRune(next)
}

func markdownDelimiterCanClose(s string, idx int, delim string) bool {
	if !strings.Contains(delim, "_") {
		return true
	}
	prev, hasPrev := markdownPrevRune(s, idx)
	next, hasNext := markdownNextRune(s, idx+len(delim))
	if !hasPrev || unicode.IsSpace(prev) {
		return false
	}
	return !hasNext || !isMarkdownWordRune(prev) || !isMarkdownWordRune(next)
}

func markdownPrevRune(s string, idx int) (rune, bool) {
	if idx <= 0 || idx > len(s) {
		return 0, false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:idx])
	if r == utf8.RuneError {
		return 0, false
	}
	return r, true
}

func markdownNextRune(s string, idx int) (rune, bool) {
	if idx < 0 || idx >= len(s) {
		return 0, false
	}
	r, _ := utf8.DecodeRuneInString(s[idx:])
	if r == utf8.RuneError {
		return 0, false
	}
	return r, true
}

func isMarkdownWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
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
