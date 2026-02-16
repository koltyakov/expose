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
