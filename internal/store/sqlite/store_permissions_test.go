package sqlite

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenCreatesOwnerOnlyDatabase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows")
	}

	dbPath := filepath.Join(t.TempDir(), "nested", "expose.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("database directory permissions = %04o, want 0700", got)
	}
}

func TestOpenTightensExistingDatabasePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows")
	}

	dbPath := filepath.Join(t.TempDir(), "expose.db")
	if err := os.WriteFile(dbPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}

	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %04o, want 0600", got)
	}
}

func TestSQLiteDiskPath(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: ":memory:"},
		{raw: "file::memory:?cache=shared"},
		{raw: "file:memdb1?mode=memory&cache=shared"},
		{raw: "expose.db", want: "expose.db", ok: true},
		{raw: "expose.db?mode=rwc", want: "expose.db", ok: true},
		{raw: "file:expose.db?mode=rwc", want: "expose.db", ok: true},
		{raw: "file:///tmp/expose.db", want: filepath.FromSlash("/tmp/expose.db"), ok: true},
	}
	for _, tt := range tests {
		got, ok := sqliteDiskPath(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("sqliteDiskPath(%q) = (%q, %v), want (%q, %v)", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}
