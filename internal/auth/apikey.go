// Package auth provides API key generation, hashing, and comparison
// utilities used by both the server and CLI admin commands.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// GenerateAPIKey returns a cryptographically random, URL-safe API key string.
func GenerateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashAPIKey returns a deterministic SHA-256 hex digest of key + pepper.
func HashAPIKey(key, pepper string) string {
	sum := sha256.Sum256([]byte(key + ":" + pepper))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeHashEquals compares two hex hash strings in constant time.
func ConstantTimeHashEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// HashPassword returns a bcrypt hash for a plain-text password.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPasswordHash reports whether the plain-text password matches hash.
func VerifyPasswordHash(hash, password string) bool {
	if hash == "" || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
