// Package releasesign authenticates immutable release checksum manifests.
// Private keys are used only by the separate release-sign build tool.
package releasesign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const (
	Repository        = "koltyakov/expose"
	AssetName         = "checksums.txt.sig"
	MaxManifestBytes  = 1 << 20
	MaxSignatureBytes = 4096
)

// KeysJSON is replaced at build time, never from the running process's environment.
// Unconfigured development builds cannot authenticate public releases.
var KeysJSON = "{}"

var keyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,80}$`)
var tagPattern = regexp.MustCompile(`^v[0-9][a-zA-Z0-9.+_-]{0,127}$`)

type Signature struct {
	Version    int    `json:"version"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	KeyID      string `json:"keyId"`
	Signature  string `json:"signature"`
}

// ParseKeys accepts BBX-style key IDs mapped to base64 raw Ed25519 public keys.
func ParseKeys(raw string) (map[string]ed25519.PublicKey, error) {
	if len(raw) > 8192 {
		return nil, errors.New("release keyring exceeds size limit")
	}
	// Read members explicitly so duplicate IDs cannot silently replace a pin.
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("release keys must be a JSON object")
	}
	keys := make(map[string]ed25519.PublicKey)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, err
		}
		id, ok := token.(string)
		if !ok || !keyIDPattern.MatchString(id) || keys[id] != nil {
			return nil, errors.New("invalid or duplicate release key ID")
		}
		var encoded string
		if err := dec.Decode(&encoded); err != nil {
			return nil, errors.New("release public keys must be base64 strings")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
			return nil, fmt.Errorf("invalid Ed25519 public key %q", id)
		}
		keys[id] = ed25519.PublicKey(key)
		if len(keys) > 16 {
			return nil, errors.New("too many release keys")
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if err := requireEOF(dec); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("no pinned release keys configured")
	}
	return keys, nil
}

func requireEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func message(repository, tag, keyID string, manifest []byte) ([]byte, error) {
	if repository != Repository || !tagPattern.MatchString(tag) || !keyIDPattern.MatchString(keyID) {
		return nil, errors.New("invalid release repository, tag, or key ID")
	}
	if len(manifest) == 0 || len(manifest) > MaxManifestBytes {
		return nil, errors.New("release manifest is empty or exceeds size limit")
	}
	// The restricted fields cannot contain newlines. No JSON canonicalization
	// is involved, and the exact checksum bytes, including the final LF, matter.
	header := "expose-release-v1\n" + repository + "\n" + tag + "\n" + keyID + "\n"
	return append([]byte(header), manifest...), nil
}

func Sign(tag, keyID string, manifest []byte, key ed25519.PrivateKey) ([]byte, error) {
	msg, err := message(Repository, tag, keyID, manifest)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	sig := Signature{1, Repository, tag, keyID, base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))}
	raw, err := json.Marshal(sig)
	return append(raw, '\n'), err
}

func Verify(tag string, manifest, raw []byte, keys map[string]ed25519.PublicKey) error {
	if len(raw) == 0 || len(raw) > MaxSignatureBytes {
		return errors.New("release signature is empty or exceeds size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var sig Signature
	if err := dec.Decode(&sig); err != nil {
		return fmt.Errorf("decode release signature: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return err
	}
	if sig.Version != 1 || sig.Tag != tag {
		return errors.New("release signature version or tag mismatch")
	}
	msg, err := message(sig.Repository, tag, sig.KeyID, manifest)
	if err != nil {
		return err
	}
	key := keys[sig.KeyID]
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("unknown release signing key %q", sig.KeyID)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(sig.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != sig.Signature {
		return errors.New("invalid Ed25519 signature encoding")
	}
	if !ed25519.Verify(key, msg, signature) {
		return errors.New("release signature verification failed")
	}
	return nil
}
