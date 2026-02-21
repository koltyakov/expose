package sqlite

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func randomSlug(length int) (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	const n = byte(len(alphabet))
	// Rejection threshold avoids modulo bias: largest multiple of n <= 256.
	const maxFair = 256 - (256 % int(n))
	slug := make([]byte, length)
	buf := make([]byte, length+16) // over-read to reduce rand calls
	filled := 0
	for filled < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("crypto/rand: %w", err)
		}
		for _, b := range buf {
			if int(b) >= maxFair {
				continue
			}
			slug[filled] = alphabet[b%n]
			filled++
			if filled == length {
				break
			}
		}
	}
	return string(slug), nil
}

func newID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func nullableString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func ensureParentDir(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
