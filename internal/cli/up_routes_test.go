package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUpStaticRootUsesConfigDirectory(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	siteDir := filepath.Join(configDir, "site")
	if err := os.Mkdir(siteDir, 0o755); err != nil {
		t.Fatalf("mkdir site: %v", err)
	}

	got, err := resolveUpStaticRoot(configDir, "./site")
	if err != nil {
		t.Fatalf("resolveUpStaticRoot error: %v", err)
	}
	if got != siteDir {
		t.Fatalf("expected %q, got %q", siteDir, got)
	}
}

func TestPrepareUpLocalRouteStartsStaticServer(t *testing.T) {
	ctx := t.Context()

	configDir := t.TempDir()
	siteDir := filepath.Join(configDir, "site")
	if err := os.Mkdir(siteDir, 0o755); err != nil {
		t.Fatalf("mkdir site: %v", err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "index.html"), []byte("hello from static route"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}

	route, staticSrv, err := prepareUpLocalRoute(ctx, configDir, upTunnelConfig{
		Name:      "docs",
		Subdomain: "docs",
		Dir:       "./site",
	}, true, nil)
	if err != nil {
		t.Fatalf("prepareUpLocalRoute error: %v", err)
	}
	defer func() { _ = staticSrv.Close() }()

	if route.LocalPort <= 0 {
		t.Fatalf("expected started local port, got %d", route.LocalPort)
	}
	if route.StaticDir != siteDir {
		t.Fatalf("expected static dir %q, got %q", siteDir, route.StaticDir)
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", route.LocalPort))
	if err != nil {
		t.Fatalf("GET static route: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read static response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if string(body) != "hello from static route" {
		t.Fatalf("unexpected body %q", string(body))
	}
}
