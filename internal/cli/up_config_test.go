package cli

import "testing"

func TestParseUpYAMLAndNormalize(t *testing.T) {
	raw := `
version: 1
protect:
  user: admin
  password_env: EXPOSE_PASSWORD
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
		t.Fatal("expected protect to be implied by password_env")
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
