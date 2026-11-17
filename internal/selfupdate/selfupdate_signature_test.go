package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/releasesign"
)

func testReleaseSignature(t *testing.T, tag string, manifest []byte) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"release": base64.StdEncoding.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	previous := releasesign.KeysJSON
	releasesign.KeysJSON = string(raw)
	t.Cleanup(func() { releasesign.KeysJSON = previous })
	signature, err := releasesign.Sign(tag, "release", manifest, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestVerifyReleaseSignature(t *testing.T) {
	manifest := []byte("manifest\n")
	signature := testReleaseSignature(t, "v1.2.3", manifest)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(signature)
	}))
	defer server.Close()
	useDownloadServer(t, server)
	rel := &Release{TagName: "v1.2.3", Assets: []Asset{
		{Name: signatureAssetName, BrowserDownloadURL: server.URL + "/checksums.txt.sig"},
	}}
	if err := verifyReleaseSignature(t.Context(), rel, manifest); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseSignature(t.Context(), rel, []byte("tampered")); err == nil {
		t.Fatal("accepted altered manifest")
	}
	rel.TagName = "v1.2.4"
	if err := verifyReleaseSignature(t.Context(), rel, manifest); err == nil {
		t.Fatal("accepted signature for a different tag")
	}
	rel.TagName = "v1.2.3"
	rel.Assets = nil
	// These former escape hatches must not affect embedded trust or enforcement.
	t.Setenv("EXPOSE_REQUIRE_SIGNATURE", "false")
	t.Setenv("EXPOSE_RELEASE_KEYS", releasesign.KeysJSON)
	if err := verifyReleaseSignature(t.Context(), rel, manifest); err == nil {
		t.Fatal("accepted unsigned release")
	}
	releasesign.KeysJSON = "{}"
	if err := verifyReleaseSignature(t.Context(), rel, manifest); err == nil {
		t.Fatal("accepted unconfigured build with environment keys")
	}
	if err := verifyReleaseSignature(t.Context(), nil, manifest); err == nil {
		t.Fatal("accepted missing metadata")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := verifyReleaseSignature(ctx, rel, manifest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestApplyInvalidSignatureDoesNotDownloadArchiveOrReplace(t *testing.T) {
	asset, err := assetNameForPlatform()
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(strings.Repeat("0", 64) + "  " + asset + "\n")
	valid := testReleaseSignature(t, "v9.9.9", manifest)
	for _, scenario := range []string{"missing", "invalid", "oversized", "unavailable", "wrong key", "altered manifest"} {
		t.Run(scenario, func(t *testing.T) {
			signature := valid
			body := manifest
			switch scenario {
			case "invalid":
				signature = []byte(`{}`)
			case "oversized":
				signature = []byte(strings.Repeat("x", releasesign.MaxSignatureBytes+1))
			case "wrong key":
				// Re-pin a different key but continue serving the old signature.
				_ = testReleaseSignature(t, "v9.9.9", manifest)
			case "altered manifest":
				body = append([]byte(" "), manifest...)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/checksums.txt":
					_, _ = w.Write(body)
				case "/checksums.txt.sig":
					if scenario == "unavailable" {
						http.NotFound(w, r)
					} else {
						_, _ = w.Write(signature)
					}
				default:
					t.Error("archive requested before successful authentication")
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			useDownloadServer(t, server)
			rel := &Release{TagName: "v9.9.9", Assets: []Asset{
				{Name: asset, BrowserDownloadURL: server.URL + "/archive"},
				{Name: checksumAssetName, BrowserDownloadURL: server.URL + "/checksums.txt"},
			}}
			if scenario != "missing" {
				rel.Assets = append(rel.Assets, Asset{Name: signatureAssetName, BrowserDownloadURL: server.URL + "/checksums.txt.sig"})
			}
			path := filepath.Join(t.TempDir(), "expose")
			if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := applyAt(t.Context(), rel, path); err == nil {
				t.Fatal("accepted unauthenticated release")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "old" {
				t.Fatalf("installation changed: %q, %v", got, err)
			}
		})
	}
}
