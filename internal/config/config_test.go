package config

import "testing"

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

func TestParseServerFlagsDBPoolDefaults(t *testing.T) {
	t.Setenv("EXPOSE_DB_MAX_OPEN_CONNS", "")
	t.Setenv("EXPOSE_DB_MAX_IDLE_CONNS", "")

	cfg, err := ParseServerFlags([]string{"--domain", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DBMaxOpenConns != 1 {
		t.Fatalf("expected DBMaxOpenConns=1, got %d", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 1 {
		t.Fatalf("expected DBMaxIdleConns=1, got %d", cfg.DBMaxIdleConns)
	}
}

func TestParseServerFlagsDBPoolValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "open must be positive",
			args: []string{"--domain", "example.com", "--db-max-open-conns", "0"},
		},
		{
			name: "idle must be positive",
			args: []string{"--domain", "example.com", "--db-max-idle-conns", "0"},
		},
		{
			name: "idle cannot exceed open",
			args: []string{"--domain", "example.com", "--db-max-open-conns", "1", "--db-max-idle-conns", "2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseServerFlags(tt.args); err == nil {
				t.Fatalf("expected parse error for args: %v", tt.args)
			}
		})
	}
}
