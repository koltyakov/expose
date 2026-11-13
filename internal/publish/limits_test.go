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
	"strings"
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

func TestIncrementalManifestSizeLimit(t *testing.T) {
	files := []domain.PublishedFile{manifestFile("index.html", "")}
	metadata, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{MaxManifestBytes + 1, 1 << 40} {
		t.Run(fmt.Sprintf("declared-size-%d", size), func(t *testing.T) {
			// Only send the header. Reject it before attempting to read or
			// allocate the declared body, even with an unlimited content budget.
			data := manifestLimitArchive(t, size, nil)
			_, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), math.MaxInt64)
			if !errors.Is(err, ErrManifestTooLarge) {
				t.Fatalf("oversized manifest header: %v", err)
			}
		})
	}
	for _, extra := range []int64{0, 1} {
		t.Run(fmt.Sprintf("compressed-body-extra-%d", extra), func(t *testing.T) {
			size := MaxManifestBytes + extra
			body := append(bytes.Clone(metadata), bytes.Repeat([]byte(" "), int(size)-len(metadata))...)
			data := manifestLimitArchive(t, size, body)
			dest := t.TempDir()
			got, err := ExtractDeltaWithLimit(bytes.NewReader(data), dest, 1)
			if extra == 0 {
				if err != nil || len(got) != 1 || got[0] != files[0] {
					t.Fatalf("manifest at limit: %+v, %v", got, err)
				}
			} else if !errors.Is(err, ErrManifestTooLarge) {
				t.Fatalf("compressed oversized manifest: %v", err)
			}
			entries, err := os.ReadDir(dest)
			if err != nil || len(entries) != 0 {
				t.Fatalf("manifest was written to disk: %v, %v", entries, err)
			}
		})
	}
}

func TestIncrementalManifestRejectsTruncationAndTrailingJSON(t *testing.T) {
	valid, err := json.Marshal([]domain.PublishedFile{manifestFile("index.html", "")})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"truncated-array": []byte(`[{"path":"index.html"`),
		"second-value":    append(bytes.Clone(valid), []byte(` []`)...),
		"trailing-junk":   append(bytes.Clone(valid), []byte(` x`)...),
	} {
		t.Run(name, func(t *testing.T) {
			data := manifestLimitArchive(t, int64(len(body)), body)
			if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), 1); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	data := manifestLimitArchive(t, 1024, nil)
	if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), 1); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated manifest body: %v", err)
	}
}

func TestManifestEntryLimit(t *testing.T) {
	files := make([]domain.PublishedFile, MaxArchiveEntries+1)
	files[0] = manifestFile("index.html", "")
	for i := 1; i < len(files); i++ {
		files[i] = manifestFile(fmt.Sprintf("file-%05d.txt", i), "")
	}
	for _, count := range []int{MaxArchiveEntries, MaxArchiveEntries + 1} {
		t.Run(fmt.Sprintf("entries-%d", count), func(t *testing.T) {
			manifest := files[:count]
			data := hostileDelta(t, manifest, nil, nil)
			// No changed files: the target count includes unchanged files,
			// and zero-byte files must not bypass this separate quota.
			got, extractErr := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), 1)
			_, localErr := DiffFiles(manifest, nil)
			_, remoteErr := DiffFiles(files[:1], manifest)
			validateErr := validateManifest(manifest, 1, true)
			for name, err := range map[string]error{
				"extract": extractErr, "validate": validateErr,
				"local preflight": localErr, "remote preflight": remoteErr,
			} {
				if count == MaxArchiveEntries && err != nil {
					t.Errorf("%s rejected limit: %v", name, err)
				}
				if count > MaxArchiveEntries && !errors.Is(err, ErrTooManyEntries) {
					t.Errorf("%s accepted excess entries: %v", name, err)
				}
			}
			if count == MaxArchiveEntries && len(got) != count {
				t.Fatalf("manifest at limit: got %d entries", len(got))
			}
		})
	}
	if err := CompleteDelta("", t.TempDir(), files, 1); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("delta completion accepted excess target entries: %v", err)
	}
}

func TestExtractArchiveEntryLimit(t *testing.T) {
	for _, directories := range []bool{false, true} {
		t.Run(fmt.Sprintf("directories-%t", directories), func(t *testing.T) {
			var archive bytes.Buffer
			gz := gzip.NewWriter(&archive)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(&tar.Header{Name: "index.html", Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			var last string
			for i := 1; i <= MaxArchiveEntries; i++ {
				last = fmt.Sprintf("entry-%05d", i)
				header := &tar.Header{Name: last, Typeflag: tar.TypeReg}
				if directories {
					header.Name += "/"
					header.Typeflag = tar.TypeDir
				}
				if err := tw.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			dest := t.TempDir()
			err := ExtractWithLimit(&archive, dest, 1)
			if !errors.Is(err, ErrTooManyEntries) {
				t.Fatalf("zero-byte entries bypassed quota: %v", err)
			}
			entries, err := os.ReadDir(dest)
			if err != nil || len(entries) != MaxArchiveEntries {
				t.Fatalf("wrong number extracted before rejection: %d, %v", len(entries), err)
			}
			if _, err := os.Stat(filepath.Join(dest, last)); !os.IsNotExist(err) {
				t.Fatalf("over-limit entry created: %v", err)
			}
			if !directories {
				// Full-upload client preflight must enforce the same file cap.
				writeFile(t, dest, last, "")
				if err := Archive(dest, io.Discard); !errors.Is(err, ErrTooManyEntries) {
					t.Fatalf("archive preflight accepted excess files: %v", err)
				}
			}
		})
	}
}

func TestIncrementalManifestStopsDecodingAtEntryLimit(t *testing.T) {
	// The final entry is deliberately malformed. Enforce the count before
	// decoding it, instead of allocating an arbitrarily large target slice.
	body := []byte("[" + strings.Repeat("{},", MaxArchiveEntries) + `{"path":`)
	data := manifestLimitArchive(t, int64(len(body)), body)
	if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), 1); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("manifest decoder did not stop at entry limit: %v", err)
	}
}

func manifestLimitArchive(t *testing.T, size int64, metadata []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: deltaManifestName, Mode: 0600, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(metadata); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil && metadata != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}
