package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteSecretFileOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not meaningful on windows")
	}

	path := filepath.Join(t.TempDir(), ".env")

	if err := writeSecretFile(path, []byte("EXPOSE_API_KEY_PEPPER=secret\n")); err != nil {
		t.Fatalf("writeSecretFile() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("new secret file perm = %o, want 600", perm)
	}

	// A pre-existing world-readable file must be tightened, not left as-is.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(path, []byte("EXPOSE_API_KEY_PEPPER=rotated\n")); err != nil {
		t.Fatalf("writeSecretFile(existing) error = %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("rewritten secret file perm = %o, want 600", perm)
	}
}
