package publish

import (
	_ "embed"
	"io"
	"net/http"
	"strings"
	"time"
)

const PresencePath = "/_expose/presence"
const PresenceScriptPath = "/_expose/presence.js"

const presenceHTMLScript = "\n<script defer src=\"" + PresenceScriptPath + "\"></script>\n"

//go:embed presence.js
var presenceScript string

func ServePresenceScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "presence.js", time.Time{}, strings.NewReader(presenceScript))
}

// Append the script without buffering HTML or changing the uploaded file. The
// browser inserts this trailing script into the body, even after </html>.
// A section reader preserves ServeContent's HEAD, range and cache handling.
type presenceHTML struct {
	file io.ReaderAt
	size int64
}

func (h presenceHTML) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	if off < h.size {
		want := min(int64(len(p)), h.size-off)
		var err error
		n, err = h.file.ReadAt(p[:want], off)
		if err != nil {
			return n, err
		}
		off += int64(n)
	}
	if off >= h.size && off-h.size < int64(len(presenceHTMLScript)) {
		n += copy(p[n:], presenceHTMLScript[off-h.size:])
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
