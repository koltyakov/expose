// Package auth provides API key generation, hashing, and comparison
// utilities used by both the server and CLI admin commands.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
