package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestApplyValidatesBeforeReplacing(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		binary []byte
		valid  bool
	}{
		{"invalid executable", []byte("not executable"), false},
		{"valid executable", valid, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			installed := filepath.Join(t.TempDir(), "expose.exe")
			if err := os.WriteFile(installed, []byte("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			asset, err := assetNameForPlatform()
			if err != nil {
				t.Fatal(err)
			}
			archive := makeTarGzArchive(t, "expose", tt.binary)
			if runtime.GOOS == "windows" {
				archive = makeZipArchive(t, "expose.exe", tt.binary)
			}
			sum := sha256.Sum256(archive)
			var mu sync.Mutex
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.URL.Path)
				mu.Unlock()
				if r.URL.Path == "/checksums.txt" {
					_, _ = fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
					return
				}
				_, _ = w.Write(archive)
			}))
			defer server.Close()
			useDownloadServer(t, server)
			t.Setenv(requireSignatureEnv, "false")
			rel := &Release{TagName: "v9.9.9", Assets: []Asset{
				{Name: asset, BrowserDownloadURL: server.URL + "/archive"},
				{Name: checksumAssetName, BrowserDownloadURL: server.URL + "/checksums.txt"},
			}}
			result, err := applyAt(t.Context(), rel, installed)
			want := "old"
			if tt.valid {
				if err != nil || result == nil || !result.Updated {
					t.Fatalf("apply failed: %+v, %v", result, err)
				}
				want = string(tt.binary)
			} else if err == nil || !strings.Contains(err.Error(), "validate binary") {
				t.Fatalf("invalid executable accepted: %+v, %v", result, err)
			}
			got, err := os.ReadFile(installed)
			if err != nil || string(got) != want {
				t.Fatalf("installed executable does not match expected bytes: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.Join(requests, ",") != "/checksums.txt,/archive" {
				t.Fatalf("unexpected verification/download order: %v", requests)
			}
		})
	}
}

func TestApplyMissingManifestDoesNotDownloadArchive(t *testing.T) {
	asset, err := assetNameForPlatform()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("download attempted before manifest validation")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	useDownloadServer(t, server)
	rel := &Release{TagName: "v9.9.9", Assets: []Asset{{Name: asset, BrowserDownloadURL: server.URL + "/archive"}}}
	if _, err = applyAt(t.Context(), rel, filepath.Join(t.TempDir(), "expose")); err == nil {
		t.Fatal("accepted missing manifest")
	}
}

func TestApplyCancellationDoesNotTouchInstallation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dir := t.TempDir()
	if _, err := applyAt(ctx, nil, filepath.Join(dir, "expose")); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("canceled update touched installation: %v, %v", entries, err)
	}
}

func TestApplyLockedInstallationDoesNotDownload(t *testing.T) {
	asset, err := assetNameForPlatform()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "expose")
	lock, err := lockExecutable(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("concurrent update attempted a download")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	useDownloadServer(t, server)
	rel := &Release{TagName: "v9.9.9", Assets: []Asset{{Name: asset, BrowserDownloadURL: server.URL + "/archive"}}}
	if _, err = applyAt(t.Context(), rel, exe); err == nil || !strings.Contains(err.Error(), "lock executable") {
		t.Fatalf("concurrent update error = %v", err)
	}
}
