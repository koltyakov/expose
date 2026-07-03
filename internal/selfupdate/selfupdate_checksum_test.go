package selfupdate

import (
	"strings"
	"testing"
)

func TestChecksumForAsset(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	manifest := "" +
		digest + "  expose_Darwin_arm64.tar.gz\n" +
		strings.Repeat("cd", 32) + "  expose_Linux_x86_64.tar.gz\n" +
		strings.Repeat("ef", 32) + " *expose_Windows_x86_64.zip\n" +
		"garbage line\n"

	tests := []struct {
		name    string
		asset   string
		want    string
		wantErr string
	}{
		{name: "plain entry", asset: "expose_Darwin_arm64.tar.gz", want: digest},
		{name: "binary-mode entry", asset: "expose_Windows_x86_64.zip", want: strings.Repeat("ef", 32)},
		{name: "missing entry", asset: "expose_Linux_arm64.tar.gz", wantErr: "no checksum entry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checksumForAsset([]byte(manifest), tt.asset)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("checksumForAsset() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("checksumForAsset() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("checksumForAsset() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChecksumForAssetMalformedDigest(t *testing.T) {
	manifest := "zz not-hex  expose_Darwin_arm64.tar.gz\n"
	if _, err := checksumForAsset([]byte(manifest), "expose_Darwin_arm64.tar.gz"); err == nil {
		t.Fatal("checksumForAsset(malformed) error = nil, want error")
	}
	short := "abcd  expose_Darwin_arm64.tar.gz\n"
	if _, err := checksumForAsset([]byte(short), "expose_Darwin_arm64.tar.gz"); err == nil || !strings.Contains(err.Error(), "malformed checksum entry") {
		t.Fatalf("checksumForAsset(short digest) error = %v, want malformed entry", err)
	}
}
