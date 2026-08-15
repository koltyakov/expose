package selfupdate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReleaseSignatureRequired(t *testing.T) {
	for _, value := range []string{"true", "1", "yes", "ON"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(requireSignatureEnv, value)
			if !releaseSignatureRequired() {
				t.Fatalf("releaseSignatureRequired() = false for %q", value)
			}
		})
	}
	t.Setenv(requireSignatureEnv, "false")
	if releaseSignatureRequired() {
		t.Fatal("releaseSignatureRequired() = true for false")
	}
}

func TestVerifyReleaseSignatureFailsClosedWithoutCosign(t *testing.T) {
	t.Setenv(requireSignatureEnv, "true")
	previous := cosignLookPath
	cosignLookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { cosignLookPath = previous })

	err := verifyReleaseSignature(context.Background(), &Release{TagName: "v1.2.3"}, []byte("manifest"))
	if err == nil {
		t.Fatal("verifyReleaseSignature() error = nil")
	}
}

func TestVerifyReleaseSignatureRunsCosign(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper is a POSIX shell script")
	}
	t.Setenv(requireSignatureEnv, "true")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums.txt.sigstore.json":
			_, _ = w.Write([]byte("bundle"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	useDownloadServer(t, server)

	cosignPath := filepath.Join(t.TempDir(), "cosign")
	if err := os.WriteFile(cosignPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := cosignLookPath
	cosignLookPath = func(string) (string, error) { return cosignPath, nil }
	t.Cleanup(func() { cosignLookPath = previous })

	rel := &Release{TagName: "v1.2.3", Assets: []Asset{
		{Name: signatureBundleAssetName, BrowserDownloadURL: server.URL + "/checksums.txt.sigstore.json"},
	}}
	if err := verifyReleaseSignature(context.Background(), rel, []byte("manifest")); err != nil {
		t.Fatalf("verifyReleaseSignature() error = %v", err)
	}
}
