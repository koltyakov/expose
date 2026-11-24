package publish

import (
	"compress/gzip"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// PrecompressedDir holds gzip variants inside a publication directory. Hidden
// paths can never be uploaded, listed in a manifest, counted in file totals or
// requested directly, so the variants cannot collide with site files.
const PrecompressedDir = ".expose-gz"

// precompressMinBytes skips files too small for compression to pay for the
// extra stat and the Vary header.
const precompressMinBytes = 1024

// compressibleTypes lists media types, besides text/*, worth precompressing.
var compressibleTypes = map[string]bool{
	"application/javascript":        true,
	"application/json":              true,
	"application/manifest+json":     true,
	"application/wasm":              true,
	"application/xhtml+xml":         true,
	"application/xml":               true,
	"application/vnd.ms-fontobject": true,
	"font/otf":                      true,
	"font/ttf":                      true,
	"image/svg+xml":                 true,
	"image/x-icon":                  true,
	"image/vnd.microsoft.icon":      true,
}

// compressibleType returns the Content-Type for name when its extension maps
// to a compressible media type, or "".
func compressibleType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ext == ".map" {
		return "application/json"
	}
	typ := mime.TypeByExtension(ext)
	if typ == "" {
		return ""
	}
	media, _, _ := strings.Cut(typ, ";")
	media = strings.TrimSpace(strings.ToLower(media))
	if strings.HasPrefix(media, "text/") || compressibleTypes[media] {
		return typ
	}
	return ""
}

func precompressedName(name string) string {
	return PrecompressedDir + "/" + name + ".gz"
}

// Precompress writes gzip variants of compressible public files in dir, an
// unpublished directory that becomes immutable once published. A file that
// is a hard link into baseDir (an unchanged file of an incremental publish)
// reuses the base publication's variant instead of being compressed again.
// Variants that save less than 10% are dropped, and their total size is
// bounded by maxBytes, so a publication uses at most twice its file budget.
func Precompress(dir, baseDir string, maxBytes int64) error {
	root, err := openArchiveRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var names []string
	if _, err := walkPublicFiles(root, nil, math.MaxInt64, func(name string, info os.FileInfo) {
		if info.Size() >= precompressMinBytes && compressibleType(name) != "" {
			names = append(names, name)
		}
	}); err != nil {
		return err
	}
	var total int64
	for _, name := range names {
		size, err := precompressFile(dir, baseDir, name)
		if err != nil {
			return err
		}
		if total += size; maxBytes > 0 && total > maxBytes {
			_ = os.Remove(filepath.Join(dir, filepath.FromSlash(precompressedName(name))))
			return nil
		}
	}
	return nil
}

func precompressFile(dir, baseDir, name string) (int64, error) {
	src := filepath.Join(dir, filepath.FromSlash(name))
	dst := filepath.Join(dir, filepath.FromSlash(precompressedName(name)))
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return 0, err
	}
	if baseDir != "" {
		if size, ok := reusePrecompressed(src, baseDir, name, dst); ok {
			return size, nil
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	written := &countingWriter{w: out}
	zw, _ := gzip.NewWriterLevel(written, gzip.BestCompression)
	_, copyErr := io.Copy(zw, in)
	closeErr := errors.Join(zw.Close(), out.Close())
	if err := errors.Join(copyErr, closeErr); err != nil {
		_ = os.Remove(dst)
		return 0, err
	}
	if written.n*10 > info.Size()*9 {
		return 0, os.Remove(dst)
	}
	return written.n, nil
}

// reusePrecompressed links the base variant when src is the same file as the
// base publication's copy.
func reusePrecompressed(src, baseDir, name, dst string) (int64, bool) {
	current, err := os.Stat(src)
	if err != nil {
		return 0, false
	}
	previous, err := os.Stat(filepath.Join(baseDir, filepath.FromSlash(name)))
	if err != nil || !os.SameFile(current, previous) {
		return 0, false
	}
	variant := filepath.Join(baseDir, filepath.FromSlash(precompressedName(name)))
	info, err := os.Lstat(variant)
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	if os.Link(variant, dst) != nil {
		return 0, false
	}
	return info.Size(), true
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// acceptsGzip reports whether the request's Accept-Encoding allows gzip.
func acceptsGzip(r *http.Request) bool {
	for _, value := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(value, ",") {
			coding, params, _ := strings.Cut(part, ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding != "gzip" && coding != "x-gzip" && coding != "*" {
				continue
			}
			q := 1.0
			for _, param := range strings.Split(params, ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
				if ok && strings.EqualFold(strings.TrimSpace(key), "q") {
					if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
						q = parsed
					}
				}
			}
			if q > 0 {
				return true
			}
		}
	}
	return false
}
