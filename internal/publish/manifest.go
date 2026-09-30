package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/domain"
)

const MaxManifestBytes = 8 << 20
const deltaManifestName = ".expose-manifest.json"

// FileTotals counts public regular files and their uncompressed bytes without
// reading file contents. Published sites have already passed upload limits.
func FileTotals(dir string) (int, int64, error) {
	root, err := openArchiveRoot(dir)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = root.Close() }()
	names, total, err := scanPublicFiles(root, nil, 0)
	if err != nil {
		return 0, 0, err
	}
	return len(names), total, nil
}

// FileSnapshot records public file metadata for lightweight watch-mode polling.
// Content checksums are computed only when a snapshot changes.
func FileSnapshot(dir string) (map[string]os.FileInfo, error) {
	root, err := openArchiveRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	names, _, err := scanArchiveFiles(root, nil)
	if err != nil {
		return nil, err
	}
	files := make(map[string]os.FileInfo, len(names))
	for _, name := range names {
		info, err := root.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("file changed during publish: %s", name)
		}
		files[name] = info
	}
	return files, nil
}

// Manifest hashes the same public regular files that Archive includes.
func Manifest(dir string) ([]domain.PublishedFile, error) {
	root, err := openArchiveRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	names, _, err := scanArchiveFiles(root, nil)
	if err != nil {
		return nil, err
	}
	files := make([]domain.PublishedFile, 0, len(names))
	for _, name := range names {
		f, info, err := openRegularFile(root, name)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, MaxExpandedBytes+1))
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		if n != info.Size() {
			return nil, fmt.Errorf("file changed during publish: %s", name)
		}
		files = append(files, domain.PublishedFile{Path: name, Checksum: hex.EncodeToString(h.Sum(nil)), Size: n})
	}
	if err := validateManifest(files, MaxExpandedBytes, true); err != nil {
		return nil, err
	}
	return files, nil
}

func openRegularFile(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("publish only accepts regular files: %s", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("file changed during publish: %s", name)
	}
	return f, info, nil
}

func validateManifest(files []domain.PublishedFile, maxBytes int64, requireIndex bool) error {
	if maxBytes <= 0 || len(files) > MaxFiles {
		return fmt.Errorf("site exceeds publish limits")
	}
	seen := make(map[string]bool, len(files))
	var total int64
	for _, file := range files {
		if err := ValidatePath(file.Path); err != nil {
			return err
		}
		if seen[file.Path] {
			return fmt.Errorf("duplicate manifest path: %s", file.Path)
		}
		seen[file.Path] = true
		checksum, err := hex.DecodeString(file.Checksum)
		if err != nil || len(checksum) != sha256.Size || file.Checksum != strings.ToLower(file.Checksum) {
			return fmt.Errorf("invalid SHA-256 checksum: %s", file.Path)
		}
		if file.Size < 0 {
			return fmt.Errorf("invalid file size: %s", file.Path)
		}
		if file.Size > maxBytes-total {
			return fmt.Errorf("%w (%d bytes)", ErrSiteTooLarge, maxBytes)
		}
		total += file.Size
	}
	// A file cannot also be a parent directory of another file.
	for name := range seen {
		parts := strings.Split(name, "/")
		for i := 1; i < len(parts); i++ {
			if seen[strings.Join(parts[:i], "/")] {
				return fmt.Errorf("conflicting manifest path: %s", name)
			}
		}
	}
	if requireIndex && !seen["index.html"] {
		return fmt.Errorf("publish requires a root index.html")
	}
	return nil
}

type FileDiff struct {
	Changed                                                []domain.PublishedFile
	Added, Updated, Deleted, Unchanged                     int
	AddedBytes, UpdatedBytes, DeletedBytes, UnchangedBytes int64
}

// DiffFiles compares content, not timestamps. Missing local paths are deletions.
func DiffFiles(local, remote []domain.PublishedFile) (FileDiff, error) {
	var diff FileDiff
	if err := validateManifest(local, MaxExpandedBytes, true); err != nil {
		return diff, err
	}
	if err := validateManifest(remote, MaxExpandedBytes, false); err != nil {
		return diff, err
	}
	previous := make(map[string]domain.PublishedFile, len(remote))
	for _, file := range remote {
		previous[file.Path] = file
	}
	for _, file := range local {
		old, exists := previous[file.Path]
		delete(previous, file.Path)
		if exists && old.Checksum == file.Checksum && old.Size == file.Size {
			diff.Unchanged++
			diff.UnchangedBytes += file.Size
			continue
		}
		diff.Changed = append(diff.Changed, file)
		if exists {
			diff.Updated++
			diff.UpdatedBytes += file.Size
		} else {
			diff.Added++
			diff.AddedBytes += file.Size
		}
	}
	diff.Deleted = len(previous)
	for _, file := range previous {
		diff.DeletedBytes += file.Size
	}
	return diff, nil
}
