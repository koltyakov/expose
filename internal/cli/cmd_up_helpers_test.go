package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUpAccessNonInteractivePaths(t *testing.T) {
	t.Setenv("ROUTE_PASSWORD", "from-env")
	t.Setenv("EXPOSE_PASSWORD", "fallback-secret")

	got, err := resolveUpAccess(upAccessConfig{
		User:     " ",
		Password: "ROUTE_PASSWORD",
	})
	if err != nil {
		t.Fatalf("resolveUpAccess(env) error = %v", err)
	}
	if got.User != "admin" || got.Password != "from-env" || !got.Protect {
		t.Fatalf("resolveUpAccess(env) = %+v", got)
	}

	got, err = resolveUpAccess(upAccessConfig{
		Protect: true,
	})
	if err != nil {
		t.Fatalf("resolveUpAccess(fallback) error = %v", err)
	}
	if got.Password != "fallback-secret" {
		t.Fatalf("resolveUpAccess(fallback) password = %q", got.Password)
	}

	got, err = resolveUpAccess(upAccessConfig{
		PasswordEnv: "LEGACY_PASSWORD",
	})
	if err != nil {
		t.Fatalf("resolveUpAccess(alias) error = %v", err)
	}
	if got.Password != "LEGACY_PASSWORD" || got.PasswordEnv != "" || !got.Protect {
		t.Fatalf("resolveUpAccess(alias) = %+v", got)
	}

	if _, err := resolveUpAccess(upAccessConfig{Password: "a", PasswordEnv: "b"}); err == nil {
		t.Fatal("expected mutually exclusive password error")
	}

	t.Setenv("EXPOSE_PASSWORD", "")
	if _, err := resolveUpAccess(upAccessConfig{Protect: true}); err == nil {
		t.Fatal("expected missing password error")
	}
}

func TestUpRouteSummaryAndHelpers(t *testing.T) {
	t.Parallel()

	cfg := upConfig{
		Access: upAccessConfig{Protect: true},
		Tunnels: []upTunnelConfig{
			{Name: "docs", Subdomain: "app", Dir: "./site", PathPrefix: "/docs", StripPrefix: true},
			{Name: "app", Subdomain: "app", Port: 3000, PathPrefix: "/"},
			{Name: "api", Subdomain: "api", Port: 8080, PathPrefix: "/api"},
		},
	}

	var out bytes.Buffer
	printUpRouteSummary(&out, cfg)
	got := out.String()

	for _, want := range []string{
		"Routes: 3 (tunnels by subdomain: 2)",
		"app/ -> http://127.0.0.1:3000 protect",
		"api/api -> http://127.0.0.1:8080 protect",
		"app/docs -> static:./site protect strip",
	} {
		if !strings.Contains(strings.ReplaceAll(got, "  ", " "), want) {
			t.Fatalf("expected %q in summary %q", want, got)
		}
	}

	if got := countDistinctSubdomains(cfg.Tunnels); got != 2 {
		t.Fatalf("countDistinctSubdomains() = %d, want 2", got)
	}
	if got := upTunnelTargetLabel(cfg.Tunnels[0]); got != "static:./site" {
		t.Fatalf("upTunnelTargetLabel(static) = %q", got)
	}
	if got := upTunnelTargetLabel(cfg.Tunnels[1]); got != "http://127.0.0.1:3000" {
		t.Fatalf("upTunnelTargetLabel(http) = %q", got)
	}
}

func TestUpWizardValidators(t *testing.T) {
	t.Parallel()

	if err := validateUpPortWizard("3000"); err != nil {
		t.Fatalf("validateUpPortWizard() error = %v", err)
	}
	if err := validateUpPortWizard("70000"); err == nil {
		t.Fatal("expected invalid port error")
	}

	if err := validateUpPathPrefixWizard("/api//v1/"); err != nil {
		t.Fatalf("validateUpPathPrefixWizard() error = %v", err)
	}
	if err := validateUpPathPrefixWizard("/api?bad=1"); err == nil {
		t.Fatal("expected invalid path prefix error")
	}

	if err := validateUpSubdomainWizard(" App "); err != nil {
		t.Fatalf("validateUpSubdomainWizard() error = %v", err)
	}
	if err := validateUpSubdomainWizard(" "); err == nil {
		t.Fatal("expected missing subdomain error")
	}

	if err := validateUpServerURLWizard("example.com"); err != nil {
		t.Fatalf("validateUpServerURLWizard() error = %v", err)
	}
	if err := validateUpServerURLWizard("http://example.com"); err == nil {
		t.Fatal("expected non-https server URL error")
	}
}

func TestRunUpEarlyErrorPaths(t *testing.T) {
	t.Chdir(t.TempDir())

	if code := runUp(context.Background(), []string{"unexpected"}); code != 2 {
		t.Fatalf("runUp(unexpected arg) = %d, want 2", code)
	}
	if code := runUp(context.Background(), []string{"-bad-flag"}); code != 2 {
		t.Fatalf("runUp(bad flag) = %d, want 2", code)
	}

	restoreIO, _ := swapPromptIO(t, "")
	defer restoreIO()

	if code := runUpInit(context.Background(), nil); code != 2 {
		t.Fatalf("runUpInit(non-interactive) = %d, want 2", code)
	}
	if code := runUpFromFile(context.Background(), filepath.Join(t.TempDir(), "missing.yml")); code != 2 {
		t.Fatalf("runUpFromFile(missing) = %d, want 2", code)
	}

	cfgPath := filepath.Join(t.TempDir(), "expose.yml")
	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
version: 1
protect:
  protect: true
tunnels:
  - subdomain: app
    port: 3000
`)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runUpFromFile(context.Background(), cfgPath); code != 2 {
		t.Fatalf("runUpFromFile(missing password) = %d, want 2", code)
	}
}
