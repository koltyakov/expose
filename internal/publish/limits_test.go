package publish

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
)

func TestLargeSiteMetadataHasNoFixedSizeCap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "")
	const size = 1 << 30
	if err := os.Truncate(filepath.Join(root, "index.html"), size); err != nil {
		t.Fatal(err)
	}
	files, err := FileSnapshot(root)
	if err != nil || files["index.html"].Size() != size {
		t.Fatalf("large file snapshot: %v, %v", files, err)
	}
	manifest := []domain.PublishedFile{manifestFile("index.html", "")}
	manifest[0].Size = size
	diff, err := DiffFiles(manifest, nil)
	if err != nil || diff.AddedBytes != size {
		t.Fatalf("large file diff: %+v, %v", diff, err)
	}
}

func TestExtractLargeEntryUsesConfiguredLimit(t *testing.T) {
	// Only send a header. With a sufficient configured budget, extraction must
	// attempt to read the content rather than reject the former 500 MiB ceiling.
	const size = 1 << 30
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "index.html", Mode: 0600, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ExtractWithLimit(bytes.NewReader(archive.Bytes()), t.TempDir(), size); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected content read, got %v", err)
	}
	if err := ExtractWithLimit(bytes.NewReader(archive.Bytes()), t.TempDir(), size-1); !errors.Is(err, ErrSiteTooLarge) {
		t.Fatalf("configured limit was not enforced: %v", err)
	}
}

func TestManifestHasNoFixedEntryOrMetadataCap(t *testing.T) {
	// Long valid paths put this manifest beyond the former 8 MiB / 20,000-file
	// limits without creating or buffering large file contents.
	files := make([]domain.PublishedFile, 21001)
	files[0] = manifestFile("index.html", "")
	for i := 1; i < len(files); i++ {
		files[i] = manifestFile(fmt.Sprintf("%0200d/%0200d.txt", i, i), "")
	}
	diff, err := DiffFiles(files, nil)
	if err != nil || diff.Added != len(files) {
		t.Fatalf("large manifest: %d entries, %v", diff.Added, err)
	}
	if err := validateManifest(files, math.MaxInt64, true); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) <= 8<<20 {
		t.Fatal("test manifest did not exceed the former metadata limit")
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: deltaManifestName, Mode: 0600, Size: int64(len(metadata)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(metadata); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, err := ExtractDeltaWithLimit(&archive, t.TempDir(), 1)
	if err != nil || len(manifest) != len(files) {
		t.Fatalf("large incremental manifest: %d entries, %v", len(manifest), err)
	}
}
