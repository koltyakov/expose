package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	signatureBundleAssetName = "checksums.txt.sigstore.json"
	requireSignatureEnv      = "EXPOSE_REQUIRE_SIGNATURE"
	releaseWorkflowIdentity  = `^https://github\.com/koltyakov/expose/\.github/workflows/release\.yml@refs/tags/.*$`
	githubActionsOIDCIssuer  = "https://token.actions.githubusercontent.com"
	maxSignatureBundleBytes  = 2 << 20
)

var cosignLookPath = exec.LookPath
var cosignCommandContext = exec.CommandContext

// verifyReleaseSignature enables a fail-closed update mode for deployments
// that install cosign and set EXPOSE_REQUIRE_SIGNATURE=true. Checksum-only
// verification remains the compatibility default for existing installations.
func verifyReleaseSignature(ctx context.Context, rel *Release, manifest []byte) error {
	if !releaseSignatureRequired() {
		return nil
	}
	if rel == nil {
		return errors.New("release metadata is required for signature verification")
	}

	cosignPath, err := cosignLookPath("cosign")
	if err != nil {
		return fmt.Errorf("%s=true requires cosign in PATH: %w", requireSignatureEnv, err)
	}

	bundleURL := releaseAssetURL(rel, signatureBundleAssetName)
	if bundleURL == "" {
		return fmt.Errorf("release %s is missing %s or %s; refusing unsigned update", rel.TagName, checksumAssetName, signatureBundleAssetName)
	}
	bundle, err := download(ctx, bundleURL)
	if err != nil {
		return fmt.Errorf("download signature bundle: %w", err)
	}
	if len(manifest) > maxChecksumBytes || len(bundle) > maxSignatureBundleBytes {
		return errors.New("release signature material exceeds size limit")
	}

	dir, err := os.MkdirTemp("", "expose-signature-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	manifestPath := filepath.Join(dir, checksumAssetName)
	bundlePath := filepath.Join(dir, signatureBundleAssetName)
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return err
	}

	cmd := cosignCommandContext(ctx, cosignPath,
		"verify-blob",
		"--bundle", bundlePath,
		"--certificate-identity-regexp", releaseWorkflowIdentity,
		"--certificate-oidc-issuer", githubActionsOIDCIssuer,
		manifestPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign verification failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func releaseAssetURL(rel *Release, name string) string {
	if rel == nil {
		return ""
	}
	for _, asset := range rel.Assets {
		if asset.Name == name {
			return strings.TrimSpace(asset.BrowserDownloadURL)
		}
	}
	return ""
}

func releaseSignatureRequired() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(requireSignatureEnv))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}
