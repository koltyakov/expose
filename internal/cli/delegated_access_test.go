package cli

import (
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/config"
)

func TestDelegatedAccessDoesNotPromptForEdgeCredentials(t *testing.T) {
	t.Setenv("EXPOSE_USER", "operator")
	t.Setenv("EXPOSE_PASSWORD", "operator-secret")
	cfg := config.ClientConfig{Protect: true, ProtectMode: access.ModeUpstreamBasic, User: "operator", Password: "operator-secret"}
	if err := promptClientPasswordIfNeeded(t.Context(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.User != "" || cfg.Password != "" {
		t.Fatal("delegation retained edge credentials")
	}
}

func TestDelegatedAccessUpConfigRoundTrip(t *testing.T) {
	t.Setenv("EXPOSE_PASSWORD", "operator-secret")
	raw := "version: 1\nprotect:\n  mode: upstream-basic\ntunnels:\n  - subdomain: app\n    port: 3000\n"
	cfg, err := parseUpYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveUpAccess(cfg.Access)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Protect || resolved.Mode != access.ModeUpstreamBasic || resolved.User != "" || resolved.Password != "" {
		t.Fatal("delegated YAML requires or retains edge credentials")
	}
	rendered := renderUpYAML(cfg)
	if !strings.Contains(rendered, "mode: 'upstream-basic'") || strings.Contains(rendered, "password:") {
		t.Fatalf("mode lost on render: %s", rendered)
	}
	parsed, err := parseUpYAML(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.normalizeAndValidate(); err != nil || parsed.Access.Mode != access.ModeUpstreamBasic {
		t.Fatal("delegated mode lost on round trip")
	}
	parsed.Tunnels[0].Port = 0
	parsed.Tunnels[0].Dir = "./private"
	if err := parsed.normalizeAndValidate(); err == nil {
		t.Fatal("delegation must not mark an unauthenticated static directory as protected")
	}
}
