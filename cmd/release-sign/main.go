// release-sign is build-time tooling, not a command shipped in expose.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/koltyakov/expose/internal/releasesign"
)

func main() {
	mode := flag.String("mode", "check", "check, sign, verify, prepare, or ldflags")
	manifest := flag.String("manifest", "checksums.txt", "checksum manifest path")
	signature := flag.String("signature", "", "signature path, defaults to <manifest>.sig")
	tag := flag.String("tag", "", "exact release tag")
	keyID := flag.String("key-id", "release", "signing key ID")
	out := flag.String("out", "tmp/release-installers", "prepared installer directory")
	flag.Parse()
	if *signature == "" {
		*signature = *manifest + ".sig"
	}
	if err := run(*mode, *manifest, *signature, *tag, *keyID, *out); err != nil {
		fmt.Fprintln(os.Stderr, "release signing:", err)
		os.Exit(1)
	}
}

func signingKey(keys map[string]ed25519.PublicKey, id, raw string) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("EXPOSE_RELEASE_PRIVATE_KEY must be one PKCS#8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid PKCS#8 signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("release signing requires an Ed25519 private key")
	}
	if !bytes.Equal(key.Public().(ed25519.PublicKey), keys[id]) {
		return nil, errors.New("private key does not match the pinned signing key ID")
	}
	return key, nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = errors.New("signing input exceeds size limit")
	}
	return data, err
}

func run(mode, manifestPath, signaturePath, tag, keyID, out string) error {
	raw := os.Getenv("EXPOSE_RELEASE_KEYS")
	if mode == "ldflags" && raw == "" {
		return nil // Ordinary local builds remain possible, but cannot update.
	}
	keys, err := releasesign.ParseKeys(raw)
	if err != nil {
		return fmt.Errorf("EXPOSE_RELEASE_KEYS: %w", err)
	}
	encoded := make(map[string]string, len(keys))
	for id, key := range keys {
		encoded[id] = base64.StdEncoding.EncodeToString(key)
	}
	compact, err := json.Marshal(encoded)
	if err != nil {
		return err
	}
	switch mode {
	case "ldflags":
		fmt.Printf("-X 'github.com/koltyakov/expose/internal/releasesign.KeysJSON=%s'", compact)
		return nil
	case "prepare":
		if err := os.MkdirAll(out, 0o755); err != nil {
			return err
		}
		for _, name := range []string{"install.sh", "install.ps1"} {
			script, err := os.ReadFile(filepath.Join("scripts", name))
			if err != nil {
				return err
			}
			if bytes.Count(script, []byte("EXPOSE_PINNED_RELEASE_KEYS")) != 1 {
				return errors.New("installer key placeholder missing or ambiguous")
			}
			script = bytes.ReplaceAll(script, []byte("EXPOSE_PINNED_RELEASE_KEYS"), compact)
			if err := os.WriteFile(filepath.Join(out, name), script, 0o755); err != nil {
				return err
			}
		}
		return nil
	case "check", "sign":
		key, err := signingKey(keys, keyID, os.Getenv("EXPOSE_RELEASE_PRIVATE_KEY"))
		if err != nil {
			return err
		}
		if mode == "check" {
			return nil
		}
		manifest, err := readLimited(manifestPath, releasesign.MaxManifestBytes)
		if err != nil {
			return err
		}
		signature, err := releasesign.Sign(tag, keyID, manifest, key)
		if err != nil {
			return err
		}
		if err := releasesign.Verify(tag, manifest, signature, keys); err != nil {
			return err
		}
		return os.WriteFile(signaturePath, signature, 0o644)
	case "verify":
		manifest, err := readLimited(manifestPath, releasesign.MaxManifestBytes)
		if err != nil {
			return err
		}
		signature, err := readLimited(signaturePath, releasesign.MaxSignatureBytes)
		if err != nil {
			return err
		}
		return releasesign.Verify(tag, manifest, signature, keys)
	default:
		return fmt.Errorf("unknown mode %q", strings.TrimSpace(mode))
	}
}
