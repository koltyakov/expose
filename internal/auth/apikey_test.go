package auth

import "testing"

func TestHashAPIKeyDeterministic(t *testing.T) {
	a := HashAPIKey("abc", "pepper")
	b := HashAPIKey("abc", "pepper")
	if a != b {
		t.Fatalf("expected deterministic hash")
	}
}

func TestConstantTimeHashEquals(t *testing.T) {
	if !ConstantTimeHashEquals("abc", "abc") {
		t.Fatalf("expected equal hashes")
	}
	if ConstantTimeHashEquals("abc", "abd") {
		t.Fatalf("expected non-equal hashes")
	}
}
