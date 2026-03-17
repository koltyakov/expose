package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndLoadUpConfigFileRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := upConfig{
		Version: 1,
		Server:  "https://example.com",
		APIKey:  "key_123",
		Access: upAccessConfig{
			Protect:  true,
			User:     "admin",
			Password: "secret",
		},
		Tunnels: []upTunnelConfig{
			{Name: "app", Subdomain: "app", Port: 3000, PathPrefix: "/", StripPrefix: false},
			{Name: "docs", Subdomain: "docs", Dir: "./site", SPA: true, Folders: true, PathPrefix: "/docs", StripPrefix: true},
		},
	}
	path := filepath.Join(t.TempDir(), "expose.yml")

	if err := writeUpConfigFile(path, cfg); err != nil {
		t.Fatalf("writeUpConfigFile() error = %v", err)
	}

	got, err := loadUpConfigFile(path)
	if err != nil {
		t.Fatalf("loadUpConfigFile() error = %v", err)
	}
	if got.Server != cfg.Server || got.APIKey != cfg.APIKey {
		t.Fatalf("loaded config mismatch: %+v", got)
	}
	if len(got.Tunnels) != 2 || !got.Tunnels[1].IsStatic() {
		t.Fatalf("loaded tunnels mismatch: %+v", got.Tunnels)
	}
}

func TestLoadUpConfigFileRejectsInvalidYAML(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "broken.yml")
	if err := os.WriteFile(path, []byte("version:\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadUpConfigFile(path); err == nil {
		t.Fatal("expected invalid YAML to fail loading")
	}
}

func TestParseUpYAMLErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "tabs unsupported",
			raw:  "version:\t1\n",
			want: "tabs are not supported",
		},
		{
			name: "unknown top key",
			raw:  "unexpected: 1\n",
			want: "unknown key",
		},
		{
			name: "protect wrong indent",
			raw:  "protect:\n user: admin\n",
			want: "protect fields must be indented by 2 spaces",
		},
		{
			name: "tunnel field without item",
			raw:  "tunnels:\n    subdomain: app\n",
			want: "tunnel fields must be nested under a '-' item",
		},
		{
			name: "unknown tunnel field",
			raw:  "tunnels:\n  - subdomain: app\n    extra: nope\n",
			want: "unknown tunnel field",
		},
		{
			name: "invalid bool",
			raw:  "tunnels:\n  - subdomain: app\n    port: 3000\n    strip_prefix: maybe\n",
			want: "invalid boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseUpYAML(tt.raw); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseUpYAML() error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestUpConfigYAMLHelpers(t *testing.T) {
	t.Parallel()

	if got := yamlQuoteString("it's ok"); got != "'it''s ok'" {
		t.Fatalf("yamlQuoteString() = %q", got)
	}

	if got, err := parseYAMLString("'it''s ok'"); err != nil || got != "it's ok" {
		t.Fatalf("parseYAMLString(single) = %q, %v", got, err)
	}
	if got, err := parseYAMLString(`"line\nbreak"`); err != nil || got != "line\nbreak" {
		t.Fatalf("parseYAMLString(double) = %q, %v", got, err)
	}
	if _, err := parseYAMLString("'unterminated"); err == nil {
		t.Fatal("expected unterminated single-quoted string error")
	}

	if got, err := parseYAMLBool("TRUE"); err != nil || !got {
		t.Fatalf("parseYAMLBool(TRUE) = %t, %v", got, err)
	}
	if _, err := parseYAMLBool("maybe"); err == nil {
		t.Fatal("expected invalid boolean error")
	}

	if key, value, hasValue, ok := splitYAMLKeyValue("name: app"); !ok || !hasValue || key != "name" || value != "app" {
		t.Fatalf("splitYAMLKeyValue() = %q %q %t %t", key, value, hasValue, ok)
	}
	if _, _, _, ok := splitYAMLKeyValue("missing"); ok {
		t.Fatal("expected malformed key/value to fail")
	}

	if got := stripYAMLComment(`value: "hash # kept" # dropped`); got != `value: "hash # kept"` {
		t.Fatalf("stripYAMLComment() = %q", got)
	}
	if got := countLeadingSpaces("   key"); got != 3 {
		t.Fatalf("countLeadingSpaces() = %d, want 3", got)
	}
}

func TestUpConfigSetTunnelFieldAndNormalizePath(t *testing.T) {
	t.Parallel()

	var tunnel upTunnelConfig
	if err := setUpTunnelField(&tunnel, "static_dir", "'./site'"); err != nil {
		t.Fatalf("setUpTunnelField(static_dir) error = %v", err)
	}
	if tunnel.Dir != "./site" {
		t.Fatalf("Dir = %q, want %q", tunnel.Dir, "./site")
	}
	if err := setUpTunnelField(&tunnel, "port", "bad"); err == nil {
		t.Fatal("expected invalid integer error")
	}
	if err := setUpTunnelField(nil, "port", "3000"); err == nil {
		t.Fatal("expected missing tunnel item error")
	}

	if got, err := normalizeUpPathPrefix("api//v1/"); err != nil || got != "/api/v1" {
		t.Fatalf("normalizeUpPathPrefix() = %q, %v", got, err)
	}
	if got, err := normalizeUpPathPrefix(""); err != nil || got != "/" {
		t.Fatalf("normalizeUpPathPrefix(empty) = %q, %v", got, err)
	}
	if _, err := normalizeUpPathPrefix("/api?q=1"); err == nil {
		t.Fatal("expected query/fragment validation error")
	}
}
