package cli

import (
	"context"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
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

	indexPath := path.Join(cleanPath, "index.html")
	if indexFile, indexInfo, ok := h.open(indexPath); ok && !indexInfo.IsDir() {
		if staticNeedsDirRedirect(r.URL.Path) {
			_ = indexFile.Close()
			redirectStaticDirectory(w, r)
			return true
		}
		defer func() { _ = indexFile.Close() }()
		serveStaticOpenedFile(w, r, indexFile, indexInfo)
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
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
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
