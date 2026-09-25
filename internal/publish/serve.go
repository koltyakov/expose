package publish

import (
	"net/http"
	"os"
	"strings"
)

// Serve resolves exact files, path.html, path/index.html, then the SPA root.
func Serve(w http.ResponseWriter, r *http.Request, dir string) {
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
		http.ServeContent(w, r, candidate, info.ModTime(), f)
		_ = f.Close()
		return
	}
	http.NotFound(w, r)
}
