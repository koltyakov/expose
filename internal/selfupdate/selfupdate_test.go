package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsNewer(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"0.3.0", "0.4.0", true},
		{"0.4.0", "0.4.0", false},
		{"0.4.0", "0.3.0", false},
		{"0.4.0", "1.0.0", true},
		{"1.0.0", "0.9.9", false},
		{"0.0.1", "0.0.2", true},
		{"0.0.2", "0.0.1", false},
		{"1.2.3", "1.2.4", true},
		{"1.2.3", "1.3.0", true},
		{"1.2.3", "2.0.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.current+"→"+tt.latest, func(t *testing.T) {
			got := isNewer(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("isNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"0.4.0", []int{0, 4, 0}},
		{"1.2.3", []int{1, 2, 3}},
		{"10.20.30", []int{10, 20, 30}},
		{"1.0.0-rc1", []int{1, 0, 0}},
		{"1.0.0+build7", []int{1, 0, 0}},
		{"bad", nil},
		{"1.2", nil},
		{"a.b.c", nil},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseSemver(tt.input)
			if tt.want == nil {
				if got != nil {
					t.Errorf("parseSemver(%q) = %v, want nil", tt.input, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseSemver(%q) = nil, want %v", tt.input, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("parseSemver(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAssetNameForPlatform(t *testing.T) {
	name, err := assetNameForPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if len(name) < 10 {
		t.Errorf("asset name too short: %q", name)
	}
	t.Logf("asset for this platform: %s", name)
}

func TestGoosToAssetOS(t *testing.T) {
	tests := []struct {
		goos    string
		want    string
		wantErr bool
	}{
		{"darwin", "Darwin", false},
		{"linux", "Linux", false},
		{"windows", "Windows", false},
		{"freebsd", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			got, err := goosToAssetOS(tt.goos)
			if (err != nil) != tt.wantErr {
				t.Errorf("goosToAssetOS(%q) error = %v, wantErr %v", tt.goos, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("goosToAssetOS(%q) = %q, want %q", tt.goos, got, tt.want)
			}
		})
	}
}

func TestGoarchToAssetArch(t *testing.T) {
	tests := []struct {
		goarch  string
		want    string
		wantErr bool
	}{
		{"amd64", "x86_64", false},
		{"arm64", "arm64", false},
		{"386", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.goarch, func(t *testing.T) {
			got, err := goarchToAssetArch(tt.goarch)
			if (err != nil) != tt.wantErr {
				t.Errorf("goarchToAssetArch(%q) error = %v, wantErr %v", tt.goarch, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("goarchToAssetArch(%q) = %q, want %q", tt.goarch, got, tt.want)
			}
		})
	}
}

func TestExtractFromTarGz(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	content := []byte("#!/bin/sh\necho hello\n")
	_ = tw.WriteHeader(&tar.Header{
		Name: "expose",
		Mode: 0o755,
		Size: int64(len(content)),
	})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gw.Close()

	got, err := extractFromTarGz(buf.Bytes(), "expose")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("extracted content mismatch")
	}
}

func TestExtractFromTarGz_NotFound(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.Close()
	_ = gw.Close()

	_, err := extractFromTarGz(buf.Bytes(), "expose")
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestReadAllWithLimit(t *testing.T) {
	got, err := readAllWithLimit(strings.NewReader("hello"), 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("expected hello, got %q", string(got))
	}
}

func TestReadAllWithLimitTooLarge(t *testing.T) {
	_, err := readAllWithLimit(strings.NewReader("hello!"), 5)
	if err == nil {
		t.Fatal("expected limit error")
	}
}

func TestReplaceBinary(t *testing.T) {
	t.Parallel()

	// Create a fake "binary" in a temp directory.
	dir := t.TempDir()
	exe := filepath.Join(dir, "expose")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	newContent := []byte("new-binary-content")
	if err := replaceBinaryAtContext(t.Context(), exe, newContent); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newContent) {
		t.Fatalf("binary content = %q, want %q", got, newContent)
	}
}

func TestReplaceBinaryCancellationPreservesInstalled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := filepath.Join(dir, "expose")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := replaceBinaryAtContext(ctx, exe, []byte("new")); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}

	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("installed binary changed to %q", got)
	}
}

func TestReplaceBinaryFailsWhenDirNotWritable(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix directory permissions and an unprivileged user")
	}

	// A directory permission failure must never cause an unlink/copy fallback.
	dir := t.TempDir()
	exe := filepath.Join(dir, "expose")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	err := replaceBinaryAtContext(t.Context(), exe, []byte("new"))
	if err == nil {
		t.Fatal("expected error when directory is not writable")
	}
	if !strings.Contains(err.Error(), "permission") && !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("expected permission-related error, got: %v", err)
	}
	got, err := os.ReadFile(exe)
	if err != nil || string(got) != "old" {
		t.Fatalf("installed binary = %q, error = %v", got, err)
	}
}

func TestUpdateLock(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "expose")
	first, err := lockExecutable(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := lockExecutable(exe)
	if err == nil {
		_ = second.Close()
		t.Fatal("concurrent update acquired the lock")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := lockExecutable(exe)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	_ = third.Close()
	if _, err = os.Stat(exe + ".update.lock"); err != nil {
		t.Fatalf("stable lock file removed: %v", err)
	}
}
