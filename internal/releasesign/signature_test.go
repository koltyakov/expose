package releasesign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignVerifyAndRotation(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("abc  archive.tar.gz\n")
	raw, err := Sign("v1.2.3", "release", manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"release": pub, "next": other}
	if err := Verify("v1.2.3", manifest, raw, keys); err != nil {
		t.Fatal(err)
	}
	next, err := Sign("v1.2.3", "next", manifest, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify("v1.2.3", manifest, next, keys); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		tag      string
		manifest []byte
		raw      []byte
		keys     map[string]ed25519.PublicKey
	}{
		{"wrong tag", "v1.2.4", manifest, raw, keys},
		{"altered bytes", "v1.2.3", append([]byte(" "), manifest...), raw, keys},
		{"missing final newline", "v1.2.3", bytes.TrimSuffix(manifest, []byte("\n")), raw, keys},
		{"wrong key", "v1.2.3", manifest, raw, map[string]ed25519.PublicKey{"release": other}},
		{"unknown key", "v1.2.3", manifest, raw, map[string]ed25519.PublicKey{"next": other}},
		{"empty keyring", "v1.2.3", manifest, raw, nil},
		{"wrong repository", "v1.2.3", manifest, bytes.ReplaceAll(raw, []byte(Repository), []byte("attacker/expose")), keys},
		{"wrong purpose", "v1.2.3", manifest, bytes.ReplaceAll(raw, []byte(`"version":1`), []byte(`"version":2`)), keys},
		{"changed key ID", "v1.2.3", manifest, bytes.ReplaceAll(raw, []byte(`"release"`), []byte(`"next"`)), keys},
		{"invalid base64", "v1.2.3", manifest, bytes.ReplaceAll(raw, []byte(`"signature":"`), []byte(`"signature":"!`)), keys},
		{"empty", "v1.2.3", manifest, nil, keys},
		{"oversized", "v1.2.3", manifest, bytes.Repeat([]byte("x"), MaxSignatureBytes+1), keys},
		{"malformed", "v1.2.3", manifest, []byte(`{`), keys},
		{"extra JSON", "v1.2.3", manifest, append(bytes.Clone(raw), []byte(`{}`)...), keys},
		{"unknown field", "v1.2.3", manifest, bytes.Replace(raw, []byte(`{`), []byte(`{"extra":true,`), 1), keys},
		{"oversized manifest", "v1.2.3", bytes.Repeat([]byte("x"), MaxManifestBytes+1), raw, keys},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := Verify(tt.tag, tt.manifest, tt.raw, tt.keys); err == nil {
				t.Fatal("accepted invalid release proof")
			}
		})
	}
	for _, tag := range []string{"", "../v1", "v1\nother", "v1/2", strings.Repeat("v", 200)} {
		if _, err := Sign(tag, "release", manifest, key); err == nil {
			t.Fatalf("accepted invalid tag %q", tag)
		}
	}
}

func TestParseKeys(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	raw := `{"release":"` + encoded + `","next":"` + encoded + `"}`
	keys, err := ParseKeys(raw)
	if err != nil || !bytes.Equal(keys["release"], pub) {
		t.Fatalf("ParseKeys: %v", err)
	}
	tooMany := map[string]string{}
	for _, id := range strings.Split("a b c d e f g h i j k l m n o p q", " ") {
		tooMany[id] = encoded
	}
	many, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		"", "{}", "null", "[]", `{"release":1}`, `{"release":"invalid"}`,
		`{"../escape":"` + encoded + `"}`, raw + "{}",
		`{"release":"` + encoded + `","release":"` + encoded + `"}`,
		string(many), strings.Repeat(" ", 8193),
	} {
		if _, err := ParseKeys(invalid); err == nil {
			t.Fatalf("accepted invalid keyring %q", invalid)
		}
	}
}
