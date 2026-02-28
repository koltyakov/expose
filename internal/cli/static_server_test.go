package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticAccessPolicyBlocksHiddenAndBackupPaths(t *testing.T) {
	t.Parallel()

	policy, err := newStaticAccessPolicy(false, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path string
		want bool
	}{
		{path: ".env", want: true},
		{path: ".git/config", want: true},
		{path: "assets/.vite/manifest.json", want: true},
		{path: "notes.txt.bak", want: true},
		{path: "index.html", want: false},
		{path: "assets/app.js", want: false},
	}
	for _, tt := range cases {
		if got := policy.Blocked(tt.path, false); got != tt.want {
			t.Fatalf("Blocked(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestStaticAccessPolicyAllowPatternOverridesHiddenBlock(t *testing.T) {
	t.Parallel()

	policy, err := newStaticAccessPolicy(false, []string{".well-known/**", "secrets/*.bak"})
	if err != nil {
		t.Fatal(err)
	}

	if policy.Blocked(".well-known/acme-challenge/token", false) {
		t.Fatal("expected allow pattern to unblock .well-known subtree")
	}
	if policy.Blocked(".well-known", true) {
		t.Fatal("expected allow pattern to unblock .well-known directory")
	}
	if policy.Blocked("secrets/keep.bak", false) {
		t.Fatal("expected allow pattern to unblock matching backup file")
	}
	if !policy.Blocked(".git/config", false) {
		t.Fatal("expected unrelated hidden path to remain blocked")
	}
}

func TestStaticFileSystemHidesBlockedFilesAndFiltersDirectoryListing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "visible.txt"), "visible")
	mustWriteStaticTestFile(t, filepath.Join(root, ".env"), "secret")
	mustWriteStaticTestFile(t, filepath.Join(root, "draft.txt.bak"), "backup")
	mustWriteStaticTestFile(t, filepath.Join(root, ".well-known", "acme-challenge", "token"), "token")

	handler := newTestStaticHandler(t, root, staticServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected hidden file to return 404, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected hidden directory file to return 404, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected directory listing to be disabled by default, got %d", rr.Code)
	}
}

func TestStaticFileSystemAllowPatternServesHiddenPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, ".well-known", "acme-challenge", "token"), "token")

	policy, err := newStaticAccessPolicy(true, []string{".well-known/**"})
	if err != nil {
		t.Fatal(err)
	}
	handler := newStaticHandler(root, policy, staticServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected allowed hidden path to return 200, got %d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "token" {
		t.Fatalf("unexpected response body %q", rr.Body.String())
	}
}

func TestStaticFileSystemBlocksNonWebAssetsWhenUnprotected(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "secret.bin"), "bin")
	mustWriteStaticTestFile(t, filepath.Join(root, "notes.md"), "md")

	policy, err := newStaticAccessPolicy(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := newStaticHandler(root, policy, staticServerOptions{Unprotected: true})

	req := httptest.NewRequest(http.MethodGet, "/secret.bin", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected non-web asset to return 404 when unprotected, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/notes.md", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected markdown asset to be served, got %d", rr.Code)
	}
}

func TestStaticFileSystemAllowsAnyFileTypeWhenProtected(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "secret.bin"), "bin")

	policy, err := newStaticAccessPolicy(false, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := newStaticHandler(root, policy, staticServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/secret.bin", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected protected static tunnel policy to allow arbitrary files, got %d", rr.Code)
	}
}

func TestDefaultStaticSubdomainDeterministicPerMachineAndPath(t *testing.T) {
	t.Parallel()

	a := defaultStaticSubdomain("machine-1", "/Users/example/site")
	b := defaultStaticSubdomain("machine-1", "/Users/example/site")
	if a == "" || b == "" {
		t.Fatal("expected non-empty deterministic static subdomain")
	}
	if a != b {
		t.Fatalf("expected same subdomain for same machine/path, got %q vs %q", a, b)
	}
	if len(a) != 6 {
		t.Fatalf("expected 6-char static subdomain, got %q (%d)", a, len(a))
	}

	c := defaultStaticSubdomain("machine-1", "/Users/example/other")
	if c == a {
		t.Fatalf("expected different subdomain for different path, got %q", c)
	}
}

func TestStaticHandlerServesDirectoryIndexWhenPresent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "docs", "index.html"), "docs home")

	handler := newTestStaticHandler(t, root, staticServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/docs/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected directory index to be served, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "docs home") {
		t.Fatalf("expected directory index body, got %q", rr.Body.String())
	}
}

func TestStaticHandlerRedirectsDirectoryToSlashWhenIndexExists(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "docs", "index.html"), "docs home")

	handler := newTestStaticHandler(t, root, staticServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("expected slash redirect for directory, got %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/docs/" {
		t.Fatalf("expected redirect to /docs/, got %q", got)
	}
}

func TestStaticHandlerAllowsDirectoryListingOnlyWithFoldersFlag(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "files", "visible.txt"), "visible")
	mustWriteStaticTestFile(t, filepath.Join(root, "files", ".env"), "secret")

	handler := newTestStaticHandler(t, root, staticServerOptions{AllowFolders: true})

	req := httptest.NewRequest(http.MethodGet, "/files/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected directory listing when --folders enabled, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "visible.txt") {
		t.Fatal("expected visible file in directory listing")
	}
	if strings.Contains(body, ".env") {
		t.Fatal("expected hidden file to be filtered from directory listing")
	}
}

func TestStaticHandlerSPAFallbackServesRootIndex(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "index.html"), "root app")

	handler := newTestStaticHandler(t, root, staticServerOptions{SPA: true})

	req := httptest.NewRequest(http.MethodGet, "/dashboard/settings", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected SPA fallback to serve root index, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "root app") {
		t.Fatalf("expected SPA index body, got %q", rr.Body.String())
	}
}

func TestStaticHandlerSPAFallbackDoesNotOverrideDirectoryIndex(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "index.html"), "root app")
	mustWriteStaticTestFile(t, filepath.Join(root, "docs", "index.html"), "docs app")

	handler := newTestStaticHandler(t, root, staticServerOptions{SPA: true})

	req := httptest.NewRequest(http.MethodGet, "/docs/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected directory index to win over SPA fallback, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "docs app") {
		t.Fatalf("expected directory index body, got %q", rr.Body.String())
	}
}

func TestStaticHandlerSPAFallbackOnlyForGetHead(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustWriteStaticTestFile(t, filepath.Join(root, "index.html"), "root app")

	handler := newTestStaticHandler(t, root, staticServerOptions{SPA: true})

	req := httptest.NewRequest(http.MethodPost, "/dashboard/settings", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected non-GET SPA miss to stay 404, got %d", rr.Code)
	}
}

func newTestStaticHandler(t *testing.T, root string, opts staticServerOptions) http.Handler {
	t.Helper()
	policy, err := newStaticAccessPolicy(opts.Unprotected, opts.AllowPatterns)
	if err != nil {
		t.Fatal(err)
	}
	return newStaticHandler(root, policy, opts)
}

func mustWriteStaticTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
