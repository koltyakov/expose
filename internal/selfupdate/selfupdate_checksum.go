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

// verifyAssetChecksum downloads the release checksum manifest and verifies
// that the SHA-256 digest of data matches the entry recorded for assetName.
// The manifest is required: releases without one are rejected rather than
// applied unverified.
func verifyAssetChecksum(ctx context.Context, rel *Release, assetName string, data []byte) error {
	var manifestURL string
	for _, a := range rel.Assets {
		if a.Name == checksumAssetName {
			manifestURL = a.BrowserDownloadURL
			break
		}
	}
	if manifestURL == "" {
		return fmt.Errorf("release %s has no %s asset; refusing unverified update", rel.TagName, checksumAssetName)
	}

	manifest, err := download(ctx, manifestURL)
	if err != nil {
		return fmt.Errorf("download %s: %w", checksumAssetName, err)
	}
	if int64(len(manifest)) > maxChecksumBytes {
		return fmt.Errorf("%s exceeds %d bytes", checksumAssetName, maxChecksumBytes)
	}

	expected, err := checksumForAsset(manifest, assetName)
	if err != nil {
		return err
	}

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
