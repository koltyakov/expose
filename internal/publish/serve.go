package publish

import (
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Serve resolves exact files, path.html, path/index.html, then the SPA root.
// dir must identify an immutable publication, with a new directory for each upload.
func Serve(w http.ResponseWriter, r *http.Request, dir string) {
	ServeWithOptions(w, r, dir, ServeOptions{})
}

type ServeOptions struct {
	WS bool
}

func ServeWithOptions(w http.ResponseWriter, r *http.Request, dir string, opts ServeOptions) {
	// Avoid heuristic caching of errors, including missing or blocked paths.
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if name != "" {
		if err := ValidatePath(name); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = root.Close() }()
	candidates := []string{"index.html"}
	if name != "" {
		candidates = []string{name, name + ".html", name + "/index.html", "index.html"}
	}
	for _, candidate := range candidates {
		f, err := root.Open(candidate)
		if err != nil {
			continue
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			continue
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Published URLs can be replaced or expire, so caches must revalidate.
		// A publication-scoped validator avoids reading the entire file and
		// changes even when two uploads have identical sizes and timestamps.
		validator := dir + "\x00" + candidate
		var content io.ReadSeeker = f
		if opts.WS && isHTML(f, candidate) {
			validator += "\x00" + presenceHTMLScript
			content = io.NewSectionReader(presenceHTML{file: f, size: info.Size()}, 0, info.Size()+int64(len(presenceHTMLScript)))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		etag := sha256.Sum256([]byte(validator))
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, etag))
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, candidate, info.ModTime(), content)
		_ = f.Close()
		return
	}
	http.NotFound(w, r)
}

func isHTML(f *os.File, name string) bool {
	typ := mime.TypeByExtension(filepath.Ext(name))
	if typ == "" {
		var buf [512]byte
		n, _ := f.ReadAt(buf[:], 0)
		typ = http.DetectContentType(buf[:n])
	}
	return strings.HasPrefix(typ, "text/html")
}
