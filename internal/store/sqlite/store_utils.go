package sqlite

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	filePath, ok := sqliteDiskPath(path)
	if !ok {
		return nil
	}
	dir := filepath.Dir(filePath)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o700)
}

// secureDatabaseFile creates a disk-backed SQLite database owner-only before
// the driver opens it. SQLite otherwise creates the file with the process
// umask (commonly 0644), even though the database contains access-cookie
// signing material, password hashes, and short-lived connect tokens.
// Existing files are tightened as well.
func secureDatabaseFile(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	filePath, ok := sqliteDiskPath(path)
	if !ok {
		return nil
	}
	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// sqliteDiskPath returns the filesystem path represented by a plain SQLite
// path or file: URI. Memory databases do not have permissions to enforce.
func sqliteDiskPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == ":memory:" {
		return "", false
	}
	if !strings.HasPrefix(raw, "file:") {
		path, _, _ := strings.Cut(raw, "?")
		return path, strings.TrimSpace(path) != ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque == ":memory:" || u.Path == ":memory:" {
		return "", false
	}
	if strings.EqualFold(u.Query().Get("mode"), "memory") {
		return "", false
	}
	path := u.Path
	if path == "" {
		path = u.Opaque
	}
	if path == "" || path == ":memory:" {
		return "", false
	}
	return filepath.FromSlash(path), true
}
