package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/koltyakov/expose/internal/releasesign"
)

const signatureAssetName = releasesign.AssetName

// Authentication is mandatory. Environment variables cannot disable it or
// replace the keys embedded in the executable.
func verifyReleaseSignature(ctx context.Context, rel *Release, manifest []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rel == nil {
		return errors.New("release metadata is required for signature verification")
	}
	keys, err := releasesign.ParseKeys(releasesign.KeysJSON)
	if err != nil {
		return err
	}
	signatureURL := releaseAssetURL(rel, signatureAssetName)
	if signatureURL == "" {
		return fmt.Errorf("release %s is missing %s; refusing unsigned update", rel.TagName, signatureAssetName)
	}
	signature, err := downloadLimited(ctx, signatureURL, releasesign.MaxSignatureBytes)
	if err != nil {
		return fmt.Errorf("download release signature: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return releasesign.Verify(rel.TagName, manifest, signature, keys)
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
