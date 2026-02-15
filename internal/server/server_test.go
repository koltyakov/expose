package server

import "testing"

func TestStableTemporarySubdomain(t *testing.T) {
	a := stableTemporarySubdomain("WORKSTATION-1", "3000")
	b := stableTemporarySubdomain("WORKSTATION-1", "3000")
	if a == "" || b == "" {
		t.Fatal("expected non-empty stable subdomain")
	}
	if a != b {
		t.Fatalf("expected deterministic value, got %s and %s", a, b)
	}
	if len(a) != 6 {
		t.Fatalf("expected short 6-char subdomain, got %q (%d)", a, len(a))
	}

	c := stableTemporarySubdomain("WORKSTATION-1", "3001")
	if c == a {
		t.Fatalf("expected different hash for different port, got same %s", c)
	}
}

func TestStableTemporarySubdomainRequiresInputs(t *testing.T) {
	if got := stableTemporarySubdomain("", "3000"); got != "" {
		t.Fatalf("expected empty hash for empty host, got %q", got)
	}
	if got := stableTemporarySubdomain("host", ""); got != "" {
		t.Fatalf("expected empty hash for empty port, got %q", got)
	}
}
