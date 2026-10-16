package netutil

import (
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
)

// AllowSPAFallback reports whether a missing file can be treated as an HTML
// page route. It is a routing hint, not a security check. Existing files must
// still be served normally and access controls must run independently.
func AllowSPAFallback(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	ext := path.Ext(strings.TrimRight(r.URL.Path, "/"))
	if ext != "" && !strings.EqualFold(ext, ".html") && !strings.EqualFold(ext, ".htm") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))) {
	case "", "document", "iframe", "frame":
	default:
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return true // Preserve extensionless routes for clients without browser headers.
	}
	var html, wildcard bool
	var explicitHTML bool
	for part := range strings.SplitSeq(accept, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		quality := 1.0
		if q, ok := params["q"]; ok {
			quality, err = strconv.ParseFloat(q, 64)
			if err != nil || quality < 0 || quality > 1 {
				continue
			}
		}
		switch mediaType {
		case "text/html", "application/xhtml+xml":
			explicitHTML = true
			html = html || quality > 0
		case "text/*", "*/*":
			wildcard = wildcard || quality > 0
		}
	}
	return html || (!explicitHTML && wildcard)
}
