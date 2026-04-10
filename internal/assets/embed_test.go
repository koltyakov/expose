package assets

import (
	"bytes"
	"testing"
)

func TestFaviconICOEmbedded(t *testing.T) {
	t.Parallel()

	if len(FaviconICO) == 0 {
		t.Fatal("FaviconICO is empty; embedded file missing")
	}

	// ICO files start with a 6-byte header: reserved (2 bytes, must be 0),
	// image type (2 bytes, 1 = ICO), and image count (2 bytes, >= 1).
	if len(FaviconICO) < 6 {
		t.Fatalf("FaviconICO too short to be a valid ICO file: %d bytes", len(FaviconICO))
	}

	// Reserved field must be 0x00 0x00
	if !bytes.Equal(FaviconICO[:2], []byte{0x00, 0x00}) {
		t.Fatalf("invalid ICO reserved field: got %x", FaviconICO[:2])
	}

	// Image type: 1 = ICO, 2 = CUR
	imageType := uint16(FaviconICO[2]) | uint16(FaviconICO[3])<<8
	if imageType != 1 && imageType != 2 {
		t.Fatalf("unexpected ICO image type: got %d, want 1 (ICO) or 2 (CUR)", imageType)
	}

	// At least one image must be present
	imageCount := uint16(FaviconICO[4]) | uint16(FaviconICO[5])<<8
	if imageCount == 0 {
		t.Fatal("ICO header reports 0 images")
	}
}
