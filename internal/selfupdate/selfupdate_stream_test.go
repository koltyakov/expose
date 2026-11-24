package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDownloadToFileHashesWhileStreaming(t *testing.T) {
	payload := strings.Repeat("release-bytes", 1000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()
	original := validateAssetURL
	validateAssetURL = func(string) error { return nil }
	t.Cleanup(func() { validateAssetURL = original })

	path := filepath.Join(t.TempDir(), "archive")
	digest, err := downloadToFile(t.Context(), server.URL, int64(len(payload)), path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(payload))
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatal("digest does not match the downloaded bytes")
	}
	if data, _ := os.ReadFile(path); string(data) != payload {
		t.Fatal("file does not hold the downloaded bytes")
	}
	if _, err := downloadToFile(t.Context(), server.URL, 10, filepath.Join(t.TempDir(), "small")); err == nil {
		t.Fatal("download over the limit accepted")
	}
}

func TestExtractBinaryFileStreamsToDisk(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "release.archive")
	if err := os.WriteFile(archive, makeTarGzArchive(t, "expose", []byte("tar-binary")), 0o600); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "expose.exe")
	if err := extractBinaryFile("expose_Linux_x86_64.tar.gz", archive, staged); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(staged); string(data) != "tar-binary" {
		t.Fatalf("staged binary = %q", data)
	}
}

func TestSweepUpdateDirsRemovesOnlyStaleOnes(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "expose")
	if err := os.WriteFile(exe, []byte("bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale, err := os.MkdirTemp(dir, updateDirPrefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "release.archive"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * staleUpdateDirAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	fresh, err := os.MkdirTemp(dir, updateDirPrefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "keep")
	if err := os.Mkdir(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(unrelated, old, old); err != nil {
		t.Fatal(err)
	}
	sweepUpdateDirs(exe, time.Now())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale update directory kept: %v", err)
	}
	for _, keep := range []string{fresh, unrelated, exe} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("%s removed: %v", keep, err)
		}
	}
}
