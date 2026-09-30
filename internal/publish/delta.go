package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/koltyakov/expose/internal/domain"
)

// CompleteDelta reuses unchanged files from an immutable base publication.
// Only target paths are retained, so deletions never mutate the live directory.
// The caller must prevent the base directory from being replaced or deleted.
func CompleteDelta(baseDir, dir string, manifest []domain.PublishedFile, maxBytes int64) error {
	if err := validateManifest(manifest, maxBytes, true); err != nil {
		return err
	}
	var base *os.Root
	if baseDir != "" {
		var err error
		base, err = os.OpenRoot(baseDir)
		if err != nil {
			return err
		}
		defer func() { _ = base.Close() }()
	}
	dest, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = dest.Close() }()
	for _, file := range manifest {
		info, err := dest.Lstat(file.Path)
		if err == nil {
			if !info.Mode().IsRegular() || info.Size() != file.Size {
				return fmt.Errorf("invalid changed file: %s", file.Path)
			}
			f, _, err := openRegularFile(dest, file.Path)
			if err != nil {
				return err
			}
			err = verifyFileContent(f, file)
			_ = f.Close()
			if err != nil {
				return err
			}
			// Rechecking also catches path aliases on case-insensitive filesystems.
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if base == nil {
			return fmt.Errorf("missing file content: %s", file.Path)
		}
		if err := reuseFile(base, baseDir, dir, file); err != nil {
			return err
		}
	}
	return nil
}

func reuseFile(base *os.Root, baseDir, dir string, file domain.PublishedFile) error {
	f, info, err := openRegularFile(base, file.Path)
	if err != nil {
		return fmt.Errorf("cannot reuse %s: %w", file.Path, err)
	}
	defer func() { _ = f.Close() }()
	if info.Size() != file.Size {
		return fmt.Errorf("unchanged file size mismatch: %s", file.Path)
	}
	if err := verifyFileContent(f, file); err != nil {
		return err
	}
	target := filepath.Join(dir, filepath.FromSlash(file.Path))
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	// Updates are extracted into fresh files, never written through these links.
	if err := os.Link(filepath.Join(baseDir, filepath.FromSlash(file.Path)), target); err == nil {
		return nil
	}
	// Fall back to a copy on filesystems that do not support hard links.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(out, f, file.Size)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func verifyFileContent(f *os.File, file domain.PublishedFile) error {
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, file.Size+1))
	if err != nil {
		return err
	}
	if n != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.Checksum {
		return fmt.Errorf("file checksum mismatch: %s", file.Path)
	}
	return nil
}
