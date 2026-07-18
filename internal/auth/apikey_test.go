package auth

import (
	"encoding/base64"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	a, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("expected URL-safe base64 key, got %q: %v", a, err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32 bytes of entropy, got %d", len(raw))
	}
	b, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected unique keys across calls")
	}
}

func TestHashAPIKeyDeterministic(t *testing.T) {
	a := HashAPIKey("abc", "pepper")
	b := HashAPIKey("abc", "pepper")
	if a != b {
		t.Fatalf("expected deterministic hash")
	}
}

func TestHashAPIKeyPepperChangesDigest(t *testing.T) {
	if HashAPIKey("abc", "pepper1") == HashAPIKey("abc", "pepper2") {
		t.Fatal("expected different peppers to produce different digests")
	}
	if HashAPIKey("abc", "pepper") == HashAPIKey("abd", "pepper") {
		t.Fatal("expected different keys to produce different digests")
	}
}

func TestConstantTimeHashEquals(t *testing.T) {
	if !ConstantTimeHashEquals("abc", "abc") {
		t.Fatalf("expected equal hashes")
	}
	if ConstantTimeHashEquals("abc", "abd") {
		t.Fatalf("expected non-equal hashes")
	}
	if ConstantTimeHashEquals("abc", "abcd") {
		t.Fatalf("expected different-length hashes to differ")
	}
	if !ConstantTimeHashEquals("", "") {
		t.Fatalf("expected empty hashes to be equal")
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

func TestVerifyPasswordHashEmptyInputs(t *testing.T) {
	hash, err := HashPassword("secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPasswordHash("", "secret-pass") {
		t.Fatal("expected empty hash to fail verification")
	}
	if VerifyPasswordHash(hash, "") {
		t.Fatal("expected empty password to fail verification")
	}
	if VerifyPasswordHash("not-a-bcrypt-hash", "secret-pass") {
		t.Fatal("expected malformed hash to fail verification")
	}
}
