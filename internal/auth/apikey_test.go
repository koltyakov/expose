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

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "secret-pass" {
		t.Fatal("expected password to be hashed")
	}
	if !VerifyPasswordHash(hash, "secret-pass") {
		t.Fatal("expected password verification to pass")
	}
	if VerifyPasswordHash(hash, "wrong") {
		t.Fatal("expected password verification to fail for wrong password")
	}
}
