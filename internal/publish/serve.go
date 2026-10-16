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

	"github.com/koltyakov/expose/internal/netutil"
)

// Serve resolves exact files, then HTML alternatives and the SPA root for page
// requests only. Missing assets return 404 instead of the root HTML document.
// dir must identify an immutable publication, with a new directory for each upload.
func Serve(w http.ResponseWriter, r *http.Request, dir string) {
	ServeWithOptions(w, r, dir, ServeOptions{})
}

type ServeOptions struct {
	WS bool
	// Roots, when set, keeps publication directories open across requests.
	Roots *RootCache
	// BeforeServe runs once after file resolution, before writing any response.
	// The selected file stays open, so the caller can release directory-lifetime
	// locks without holding them while a slow client receives the response.
	BeforeServe func()
}

func ServeWithOptions(w http.ResponseWriter, r *http.Request, dir string, opts ServeOptions) {
	ready := func() {
		if opts.BeforeServe != nil {
			opts.BeforeServe()
		}
	}
	// Avoid heuristic caching of errors, including missing or blocked paths.
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		ready()
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if name != "" {
		if err := ValidatePath(name); err != nil {
			ready()
			http.NotFound(w, r)
			return
		}
	}
	root, cached, err := opts.Roots.open(dir)
	if err != nil {
		ready()
		http.NotFound(w, r)
		return
	}
	if !cached {
		defer func() { _ = root.Close() }()
	}
	candidates := []string{"index.html"}
	if name != "" {
		candidates = []string{name, name + ".html", name + "/index.html", "index.html"}
	}
	var pageFallback, directory bool
	for i, candidate := range candidates {
		if i == 1 {
			// Inspect routing hints only after the exact file misses. A real
			// directory may still serve its own index for any request headers.
			pageFallback = netutil.AllowSPAFallback(r)
		}
		if i > 0 && !pageFallback && (i != 2 || !directory) {
			continue
		}
		f, err := root.Open(candidate)
		if err != nil {
			continue
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			if i == 0 && err == nil {
				directory = info.IsDir()
			}
			_ = f.Close()
			continue
		}
		defer func() { _ = f.Close() }()
		if name != "" && candidate != name {
			w.Header().Add("Vary", "Accept, Sec-Fetch-Dest")
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
		ready()
		http.ServeContent(&publicationContentWriter{ResponseWriter: w}, r, candidate, info.ModTime(), content)
		return
	}
	ready()
	http.NotFound(w, r)
}

// ServeContent removes cache headers on range errors. Restore no-store at the
// point it commits any error, including precondition failures.
type publicationContentWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *publicationContentWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *publicationContentWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	if status >= http.StatusBadRequest {
		w.Header().Set("Cache-Control", "no-store")
	}
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *publicationContentWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// Keep the underlying writer's optimized copy path when it has one. Optional
// controller methods such as Flush are reached through Unwrap instead.
func (w *publicationContentWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{w}, r)
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
