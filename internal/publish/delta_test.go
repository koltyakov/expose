package publish

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
)

func manifestFile(name, content string) domain.PublishedFile {
	hash := sha256.Sum256([]byte(content))
	return domain.PublishedFile{Path: name, Checksum: hex.EncodeToString(hash[:]), Size: int64(len(content))}
}

func TestManifestAndDiff(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "home")
	writeFile(t, root, "assets/empty.txt", "")
	writeFile(t, root, ".env", "secret")
	writeFile(t, root, "node_modules/pkg/index.js", "private")
	writeFile(t, root, ".well-known/security.txt", "public")
	files, err := Manifest(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.PublishedFile{manifestFile(".well-known/security.txt", "public"), manifestFile("assets/empty.txt", ""), manifestFile("index.html", "home")}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("manifest: %+v, want %+v", files, want)
	}
	remote := []domain.PublishedFile{manifestFile("index.html", "old!"), manifestFile("old.txt", "delete"), manifestFile("assets/empty.txt", "")}
	diff, err := DiffFiles(files, remote)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Added != 1 || diff.Updated != 1 || diff.Deleted != 1 || diff.Unchanged != 1 || len(diff.Changed) != 2 {
		t.Fatalf("wrong content diff: %+v", diff)
	}
	if diff.AddedBytes != 6 || diff.UpdatedBytes != 4 || diff.DeletedBytes != 6 || diff.UnchangedBytes != 0 {
		t.Fatalf("wrong content sizes: %+v", diff)
	}
	if err := os.Symlink("index.html", filepath.Join(root, "link.html")); err != nil {
		t.Fatal(err)
	}
	if _, err := Manifest(root); err == nil {
		t.Fatal("manifest accepted a symlink")
	}
}

func TestArchiveDeltaWithIgnoredEmptyFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "home")
	writeFile(t, root, "new.txt", "")
	files := []domain.PublishedFile{manifestFile("index.html", "home")}
	var archive bytes.Buffer
	if err := ArchiveDeltaWithIgnoredEmptyFiles(root, &archive, files, nil, []string{"new.txt"}, nil); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	got, err := ExtractDeltaWithLimit(&archive, dest, MaxExpandedBytes)
	if err != nil || !reflect.DeepEqual(got, files) {
		t.Fatalf("ignored placeholder appears in manifest: %+v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("ignored placeholder was archived: %v", err)
	}
	archive.Reset()
	if err := ArchiveDelta(root, &archive, files, nil, nil); err == nil {
		t.Fatal("ordinary delta accepted a missing file in the manifest")
	}
	writeFile(t, root, "new.txt", "content")
	archive.Reset()
	if err := ArchiveDeltaWithIgnoredEmptyFiles(root, &archive, files, nil, []string{"new.txt"}, nil); err == nil {
		t.Fatal("ignored placeholder gained content without requiring a new comparison")
	}
}

func TestDiffFilesCategorySizes(t *testing.T) {
	local := []domain.PublishedFile{
		manifestFile("index.html", "new"),
		manifestFile("updated.txt", strings.Repeat("x", 512)),
		manifestFile("new.txt", strings.Repeat("x", 128)),
		manifestFile("new-empty.txt", ""),
		manifestFile("keep.txt", strings.Repeat("x", 256)),
		manifestFile("keep-empty.txt", ""),
	}
	remote := []domain.PublishedFile{
		manifestFile("index.html", "old index"),
		manifestFile("updated.txt", strings.Repeat("x", 1024)),
		manifestFile("deleted.txt", strings.Repeat("x", 1024)),
		manifestFile("deleted-again.txt", strings.Repeat("x", 2048)),
		manifestFile("keep.txt", strings.Repeat("x", 256)),
		manifestFile("keep-empty.txt", ""),
	}
	diff, err := DiffFiles(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Added != 2 || diff.Updated != 2 || diff.Deleted != 2 || diff.Unchanged != 2 {
		t.Fatalf("wrong category counts: %+v", diff)
	}
	// Updated bytes are the full new contents, not the old size or the size delta.
	if diff.AddedBytes != 128 || diff.UpdatedBytes != 515 || diff.DeletedBytes != 3072 || diff.UnchangedBytes != 256 {
		t.Fatalf("wrong category sizes: %+v", diff)
	}
	initial, err := DiffFiles(local, nil)
	if err != nil || initial.Added != 6 || initial.AddedBytes != 899 || initial.UpdatedBytes != 0 || initial.DeletedBytes != 0 || initial.UnchangedBytes != 0 {
		t.Fatalf("wrong initial publication sizes: %+v, %v", initial, err)
	}
	unchanged, err := DiffFiles(local, local)
	if err != nil || unchanged.Unchanged != 6 || unchanged.UnchangedBytes != 899 || unchanged.AddedBytes != 0 || unchanged.UpdatedBytes != 0 || unchanged.DeletedBytes != 0 {
		t.Fatalf("wrong unchanged publication sizes: %+v, %v", unchanged, err)
	}
}

func TestFileTotalsUseMetadataAndPublicFilePolicy(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "home")
	writeFile(t, root, "assets/empty.txt", "")
	writeFile(t, root, ".well-known/security.txt", "public")
	writeFile(t, root, ".env", "private")
	writeFile(t, root, "node_modules/pkg/index.js", "private")
	count, size, err := FileTotals(root)
	if err != nil || count != 3 || size != 10 {
		t.Fatalf("wrong public file totals: %d, %d, %v", count, size, err)
	}
	// Counting an already-published site does not impose the CLI archive ceiling
	// or read its contents. A sparse file keeps this test's disk usage small.
	if err := os.Truncate(filepath.Join(root, "index.html"), MaxExpandedBytes+1); err != nil {
		t.Fatal(err)
	}
	count, size, err = FileTotals(root)
	if err != nil || count != 3 || size != MaxExpandedBytes+7 {
		t.Fatalf("wrong large-file metadata totals: %d, %d, %v", count, size, err)
	}
}

func TestIncrementalArchiveRoundTrip(t *testing.T) {
	base, local, dest := t.TempDir(), t.TempDir(), t.TempDir()
	for _, root := range []string{base, local} {
		writeFile(t, root, "index.html", "home")
		writeFile(t, root, "assets/keep.js", "unchanged")
		writeFile(t, root, "updated.txt", "old")
	}
	writeFile(t, base, "removed.txt", "removed")
	writeFile(t, base, "to-directory", "old file")
	writeFile(t, base, "to-file/child.txt", "old child")
	writeFile(t, local, "updated.txt", "new")
	writeFile(t, local, "new.txt", "new file")
	writeFile(t, local, "to-directory/child.txt", "new child")
	writeFile(t, local, "to-file", "new file")
	writeFile(t, local, ".env", "secret")
	remote, err := Manifest(base)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Manifest(local)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	var progress ArchiveProgress
	if err := ArchiveDelta(local, &buf, files, remote, func(p ArchiveProgress) { progress = p }); err != nil {
		t.Fatal(err)
	}
	if progress.Files != 4 || progress.TotalFiles != 4 || progress.Bytes != progress.TotalBytes {
		t.Fatalf("progress included unchanged files: %+v", progress)
	}
	manifest, err := ExtractDeltaWithLimit(bytes.NewReader(buf.Bytes()), dest, MaxExpandedBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "assets/keep.js", "removed.txt", ".env", deltaManifestName} {
		if _, err := os.Stat(filepath.Join(dest, name)); !os.IsNotExist(err) {
			t.Fatalf("delta included %s: %v", name, err)
		}
	}
	if err := CompleteDelta(base, dest, manifest, MaxExpandedBytes); err != nil {
		t.Fatal(err)
	}
	got, err := Manifest(dest)
	if err != nil || !reflect.DeepEqual(got, files) {
		t.Fatalf("merged manifest: %+v, %v, want %+v", got, err, files)
	}
	before, _ := os.Stat(filepath.Join(base, "assets/keep.js"))
	after, _ := os.Stat(filepath.Join(dest, "assets/keep.js"))
	if !os.SameFile(before, after) {
		t.Fatal("unchanged file was not reused with a hard link")
	}
	if _, err := os.Stat(filepath.Join(base, "removed.txt")); err != nil {
		t.Fatal("deletion mutated the base directory")
	}
	// Full uploads must not accept the incremental control entry.
	if err := Extract(bytes.NewReader(buf.Bytes()), t.TempDir()); err == nil {
		t.Fatal("normal extraction accepted an incremental archive")
	}
}

func TestIncrementalArchiveInitialAndNoChanges(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "home")
	writeFile(t, root, "empty.txt", "")
	files, err := Manifest(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, initial := range []bool{true, false} {
		var remote []domain.PublishedFile
		base := ""
		if !initial {
			remote, base = files, root
		}
		var buf bytes.Buffer
		var progress ArchiveProgress
		if err := ArchiveDelta(root, &buf, files, remote, func(p ArchiveProgress) { progress = p }); err != nil {
			t.Fatal(err)
		}
		if initial && progress.Files != 2 || !initial && (progress.Files != 0 || progress.Bytes != 0) {
			t.Fatalf("initial=%v: unexpected progress %+v", initial, progress)
		}
		dest := t.TempDir()
		manifest, err := ExtractDeltaWithLimit(&buf, dest, 4)
		if err != nil {
			t.Fatal(err)
		}
		if err := CompleteDelta(base, dest, manifest, 4); err != nil {
			t.Fatal(err)
		}
		got, err := Manifest(dest)
		if err != nil || !reflect.DeepEqual(got, files) {
			t.Fatalf("initial=%v: wrong final files: %+v, %v", initial, got, err)
		}
	}
}

func TestIncrementalArchiveRejectsLocalChangesAfterHashing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "old")
	files, err := Manifest(root)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "index.html", "new")
	if err := ArchiveDelta(root, &bytes.Buffer{}, files, nil, nil); err == nil || !strings.Contains(err.Error(), "file changed") {
		t.Fatalf("changed content was accepted: %v", err)
	}
	writeFile(t, root, "extra.txt", "new")
	if err := ArchiveDelta(root, &bytes.Buffer{}, files, nil, nil); err == nil || !strings.Contains(err.Error(), "folder changed") {
		t.Fatalf("changed file list was accepted: %v", err)
	}
}

func hostileDelta(t *testing.T, manifest any, entries []tar.Header, contents []string) []byte {
	t.Helper()
	metadata, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: deltaManifestName, Typeflag: tar.TypeReg, Size: int64(len(metadata))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(metadata); err != nil {
		t.Fatal(err)
	}
	for i, header := range entries {
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if i < len(contents) {
			if _, err := tw.Write([]byte(contents[i])); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestIncrementalArchiveRejectsHostileManifests(t *testing.T) {
	index := manifestFile("index.html", "home")
	badChecksum := index
	badChecksum.Checksum = "not-sha256"
	badSize := index
	badSize.Size = -1
	for name, manifest := range map[string]any{
		"traversal":     []domain.PublishedFile{index, manifestFile("../outside", "")},
		"hidden":        []domain.PublishedFile{index, manifestFile(".env", "")},
		"dependency":    []domain.PublishedFile{index, manifestFile("vendor/pkg.js", "")},
		"duplicate":     []domain.PublishedFile{index, index},
		"checksum":      []domain.PublishedFile{badChecksum},
		"size":          []domain.PublishedFile{badSize},
		"missing index": []domain.PublishedFile{manifestFile("other.html", "")},
		"empty":         []domain.PublishedFile{},
		"null":          nil,
		"conflict":      []domain.PublishedFile{index, manifestFile("assets", ""), manifestFile("assets/file.js", "")},
		"wrong type":    map[string]string{"path": "index.html"},
	} {
		t.Run(name, func(t *testing.T) {
			data := hostileDelta(t, manifest, nil, nil)
			if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), MaxExpandedBytes); err == nil {
				t.Fatal("accepted hostile manifest")
			}
		})
	}
	// The limit includes unchanged files, even though the archive has no content.
	data := hostileDelta(t, []domain.PublishedFile{index, manifestFile("unchanged.js", "large")}, nil, nil)
	if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), 8); !errors.Is(err, ErrSiteTooLarge) {
		t.Fatalf("combined final size limit was not enforced: %v", err)
	}
}

func TestIncrementalArchiveRejectsHostileEntries(t *testing.T) {
	index := manifestFile("index.html", "home")
	for name, entries := range map[string][]tar.Header{
		"unexpected": {{Name: "other.txt", Typeflag: tar.TypeReg}},
		"symlink":    {{Name: "index.html", Typeflag: tar.TypeSymlink, Linkname: "/outside"}},
		"hardlink":   {{Name: "index.html", Typeflag: tar.TypeLink, Linkname: "/outside"}},
		"directory":  {{Name: "index.html", Typeflag: tar.TypeDir}},
		"wrong size": {{Name: "index.html", Typeflag: tar.TypeReg}},
		"traversal":  {{Name: "../outside", Typeflag: tar.TypeReg}},
		"duplicate":  {{Name: "index.html", Typeflag: tar.TypeReg, Size: 4}, {Name: "index.html", Typeflag: tar.TypeReg, Size: 4}},
	} {
		t.Run(name, func(t *testing.T) {
			var contents []string
			if name == "duplicate" {
				contents = []string{"home", "home"}
			}
			data := hostileDelta(t, []domain.PublishedFile{index}, entries, contents)
			if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), MaxExpandedBytes); err == nil {
				t.Fatal("accepted hostile entry")
			}
		})
	}
	data := hostileDelta(t, []domain.PublishedFile{index}, []tar.Header{{Name: "index.html", Typeflag: tar.TypeReg, Size: 4}}, []string{"evil"})
	if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), MaxExpandedBytes); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("changed content checksum was not verified: %v", err)
	}
	data = hostileDelta(t, []domain.PublishedFile{index}, nil, nil)
	data[len(data)-8] ^= 0xff
	if _, err := ExtractDeltaWithLimit(bytes.NewReader(data), t.TempDir(), MaxExpandedBytes); err == nil {
		t.Fatal("accepted corrupt gzip trailer")
	}
}

func TestCompleteDeltaRejectsMissingOrChangedBaseFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "home")
	files := []domain.PublishedFile{manifestFile("index.html", "home")}
	if err := CompleteDelta("", t.TempDir(), files, MaxExpandedBytes); err == nil {
		t.Fatal("initial upload accepted missing content")
	}
	writeFile(t, root, "index.html", "evil")
	if err := CompleteDelta(root, t.TempDir(), files, MaxExpandedBytes); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("reused content checksum was not verified: %v", err)
	}
	if err := CompleteDelta("", root, files, MaxExpandedBytes); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("changed content checksum was not verified: %v", err)
	}
}
