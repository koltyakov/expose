package cli

import "testing"

func TestParseUpYAMLAndNormalize(t *testing.T) {
	raw := `
version: 1
protect:
  user: admin
  password: EXPOSE_PASSWORD
tunnels:
  - name: frontend
    subdomain: myapp
    port: 3000
    path_prefix: /
    strip_prefix: false
  - name: api
    subdomain: myapp
    port: 8080
    path_prefix: /api/
    strip_prefix: true
`
	cfg, err := parseUpYAML(raw)
	if err != nil {
		t.Fatalf("parseUpYAML error: %v", err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		t.Fatalf("normalizeAndValidate error: %v", err)
	}
	if !cfg.Access.Protect {
		t.Fatal("expected protect to be implied by password")
	}
	if got := cfg.Tunnels[1].PathPrefix; got != "/api" {
		t.Fatalf("expected normalized path_prefix /api, got %q", got)
	}
}

func TestParseUpYAMLLegacyAccessAlias(t *testing.T) {
	raw := `
version: 1
access:
  protect: true
  user: admin
  password_env: EXPOSE_PASSWORD
tunnels:
  - subdomain: myapp
    port: 3000
`
	cfg, err := parseUpYAML(raw)
	if err != nil {
		t.Fatalf("parseUpYAML legacy alias error: %v", err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		t.Fatalf("normalizeAndValidate legacy alias error: %v", err)
	}
	if !cfg.Access.Protect {
		t.Fatal("expected legacy access alias to set protect")
	}
	if got := cfg.Access.Password; got != "EXPOSE_PASSWORD" {
		t.Fatalf("expected password_env to normalize into password, got %q", got)
	}
	if got := cfg.Access.PasswordEnv; got != "" {
		t.Fatalf("expected password_env alias to be cleared after normalization, got %q", got)
	}
}

func TestUpConfigRejectsDuplicateRoute(t *testing.T) {
	cfg := upConfig{
		Version: 1,
		Tunnels: []upTunnelConfig{
			{Name: "a", Subdomain: "myapp", Port: 3000, PathPrefix: "/"},
			{Name: "b", Subdomain: "myapp", Port: 8080, PathPrefix: "/"},
		},
	}
	if err := cfg.normalizeAndValidate(); err == nil {
		t.Fatal("expected duplicate route error")
	}
}

func TestParseUpYAMLStaticRoute(t *testing.T) {
	raw := `
version: 1
tunnels:
  - name: docs
    subdomain: myapp
    dir: ./site
    spa: true
    folders: true
    path_prefix: /docs/
    strip_prefix: true
`
	cfg, err := parseUpYAML(raw)
	if err != nil {
		t.Fatalf("parseUpYAML error: %v", err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		t.Fatalf("normalizeAndValidate error: %v", err)
	}
	route := cfg.Tunnels[0]
	if !route.IsStatic() {
		t.Fatal("expected route to be static")
	}
	if route.Dir != "./site" {
		t.Fatalf("expected dir to be preserved, got %q", route.Dir)
	}
	if !route.SPA || !route.Folders {
		t.Fatalf("expected static flags to be preserved, got spa=%t folders=%t", route.SPA, route.Folders)
	}
	if route.PathPrefix != "/docs" {
		t.Fatalf("expected normalized path_prefix /docs, got %q", route.PathPrefix)
	}
}

func TestUpConfigRejectsPortAndDirTogether(t *testing.T) {
	cfg := upConfig{
		Version: 1,
		Tunnels: []upTunnelConfig{
			{Name: "docs", Subdomain: "myapp", Port: 3000, Dir: "./site"},
		},
	}
	if err := cfg.normalizeAndValidate(); err == nil {
		t.Fatal("expected mixed port/dir validation error")
	}
}

func TestUpConfigRejectsStaticFlagsWithoutDir(t *testing.T) {
	cfg := upConfig{
		Version: 1,
		Tunnels: []upTunnelConfig{
			{Name: "app", Subdomain: "myapp", Port: 3000, SPA: true},
		},
	}
	if err := cfg.normalizeAndValidate(); err == nil {
		t.Fatal("expected static-only flag validation error")
	}
}
