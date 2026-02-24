package config

import (
	"strings"
	"testing"
)

func TestNormalizeDomainHost(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"example.com":                 "example.com",
		"https://example.com/path":    "example.com",
		"http://EXAMPLE.com:443/abc":  "example.com",
		"  sub.example.com.  ":        "sub.example.com",
		"https://[2001:db8::1]:10443": "2001:db8::1",
	}

	for in, want := range tests {
		if got := normalizeDomainHost(in); got != want {
			t.Fatalf("normalizeDomainHost(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestParseClientFlagsPasswordSourcesAndTrim(t *testing.T) {
	t.Setenv("EXPOSE_PASSWORD", " from-env ")

	cfg, err := ParseClientFlags([]string{"--port", "8080"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "from-env" {
		t.Fatalf("expected trimmed env password, got %q", cfg.Password)
	}
}

func TestParseClientFlagsPasswordLengthValidation(t *testing.T) {
	t.Setenv("EXPOSE_PASSWORD", strings.Repeat("a", 257))
	_, err := ParseClientFlags([]string{"--port", "8080"})
	if err == nil {
		t.Fatal("expected password length validation error")
	}
}

func TestParseClientFlagsProtectFlag(t *testing.T) {
	cfg, err := ParseClientFlags([]string{"--port", "8080", "--protect"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Protect {
		t.Fatal("expected --protect to enable protection")
	}
}

func TestParseClientFlagsPasswordEnablesProtect(t *testing.T) {
	t.Setenv("EXPOSE_PASSWORD", "abc")
	cfg, err := ParseClientFlags([]string{"--port", "8080"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Protect {
		t.Fatal("expected password to imply protection enabled")
	}
}

func TestNormalizeListenAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"10443", ":10443"},
		{":10443", ":10443"},
		{"0.0.0.0:10443", "0.0.0.0:10443"},
		{"[::1]:10443", "[::1]:10443"},
		{"443", ":443"},
		{":443", ":443"},
		{"  10443  ", ":10443"},
		{"", ""},
		{"localhost:8080", "localhost:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := normalizeListenAddr(tt.in)
			if got != tt.want {
				t.Errorf("normalizeListenAddr(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseServerFlagsListenNormalization(t *testing.T) {
	t.Setenv("EXPOSE_LISTEN_HTTPS", "10443")
	t.Setenv("EXPOSE_LISTEN_HTTP_CHALLENGE", "10080")

	cfg, err := ParseServerFlags([]string{"--domain", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenHTTPS != ":10443" {
		t.Fatalf("expected :10443, got %q", cfg.ListenHTTPS)
	}
	if cfg.ListenHTTP != ":10080" {
		t.Fatalf("expected :10080, got %q", cfg.ListenHTTP)
	}
}

func TestParseClientFlagsUserDefaultAndOverride(t *testing.T) {
	cfg, err := ParseClientFlags([]string{"--port", "8080"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "admin" {
		t.Fatalf("expected default user admin, got %q", cfg.User)
	}

	t.Setenv("EXPOSE_USER", "alice")
	cfg, err = ParseClientFlags([]string{"--port", "8080"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "alice" {
		t.Fatalf("expected EXPOSE_USER override, got %q", cfg.User)
	}

	t.Setenv("EXPOSE_USER", "")
	cfg, err = ParseClientFlags([]string{"--port", "8080"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "admin" {
		t.Fatalf("expected empty EXPOSE_USER to fallback to admin, got %q", cfg.User)
	}
}
