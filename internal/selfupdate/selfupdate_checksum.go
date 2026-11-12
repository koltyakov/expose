package selfupdate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// checksumAssetName is the goreleaser-published checksum manifest attached to
// every release (see checksum.name_template in .goreleaser.yaml).
const checksumAssetName = "checksums.txt"

const maxChecksumBytes = 1 << 20 // 1 MiB

// releaseChecksum authenticates the manifest before the archive is downloaded.
func releaseChecksum(ctx context.Context, rel *Release, assetName string) (string, error) {
	var manifestURL string
	for _, a := range rel.Assets {
		if a.Name == checksumAssetName {
			manifestURL = a.BrowserDownloadURL
			break
		}
	}
	if manifestURL == "" {
		return "", fmt.Errorf("release %s has no %s asset; refusing unverified update", rel.TagName, checksumAssetName)
	}

	manifest, err := downloadLimited(ctx, manifestURL, maxChecksumBytes)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", checksumAssetName, err)
	}
	if err := verifyReleaseSignature(ctx, rel, manifest); err != nil {
		return "", fmt.Errorf("verify release signature: %w", err)
	}
	return checksumForAsset(manifest, assetName)
}

func verifyChecksum(assetName string, data []byte, expected string) error {
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", assetName, expected, actual)
	}
	return nil
}

// checksumForAsset extracts the hex SHA-256 digest recorded for assetName
// from a goreleaser checksums.txt manifest ("<hex>  <filename>" per line).
func checksumForAsset(manifest []byte, assetName string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(manifest))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		if fields[1] == assetName || fields[1] == "*"+assetName {
			digest := strings.ToLower(fields[0])
			if len(digest) != sha256.Size*2 {
				return "", fmt.Errorf("malformed checksum entry for %s", assetName)
			}
			if _, err := hex.DecodeString(digest); err != nil {
				return "", fmt.Errorf("malformed checksum entry for %s", assetName)
			}
			return digest, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read %s: %w", checksumAssetName, err)
	}
	return "", errors.New("no checksum entry for " + assetName)
}
