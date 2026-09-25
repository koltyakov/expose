// Package publish implements the archive format and file policy for hosted sites.
package publish

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const MaxArchiveBytes int64 = 100 << 20
const MaxExpandedBytes int64 = 500 << 20
const MaxFiles = 20000

var ErrSiteTooLarge = errors.New("site exceeds maximum extracted size")

// ValidatePath rejects unsafe names rather than silently omitting private files.
func ValidatePath(name string) error {
	if !fs.ValidPath(name) || name == "." || strings.ContainsAny(name, "\\:\x00") {
		return fmt.Errorf("unsafe publish path %q", name)
	}
	for _, part := range strings.Split(strings.ToLower(name), "/") {
		if strings.HasPrefix(part, ".") && part != ".well-known" {
			return fmt.Errorf("publishing hidden files is blocked: %s", name)
		}
		switch part {
		case "node_modules", "vendor", "id_rsa", "id_ed25519", "id_ecdsa", "credentials", "credentials.json", "secrets", "secrets.json", "secrets.yml", "secrets.yaml", "service-account.json", "serviceaccount.json", "desktop.ini":
			return fmt.Errorf("publishing dependency or secret paths is blocked: %s", name)
		}
		for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".db", ".sqlite", ".sqlite3", ".sql", ".bak", ".env"} {
			if strings.HasSuffix(part, suffix) {
				return fmt.Errorf("publishing secret or backup files is blocked: %s", name)
			}
		}
	}
	return nil
}

// Archive validates the entire tree before writing a gzip-compressed tar archive.
func Archive(dir string, dst io.Writer) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := ValidatePath(filepath.Base(abs)); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	var names []string
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if err := ValidatePath(name); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("publish only accepts regular files: %s", name)
		}
		total += info.Size()
		names = append(names, name)
		if total > MaxExpandedBytes || len(names) > MaxFiles {
			return fmt.Errorf("site exceeds publish limits")
		}
		return nil
	})
	if err != nil {
		return err
	}
	index, err := root.Stat("index.html")
	if err != nil || !index.Mode().IsRegular() {
		return fmt.Errorf("publish requires a root index.html")
	}
	zw := gzip.NewWriter(dst)
	tw := tar.NewWriter(zw)
	total = 0
	for _, name := range names {
		before, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !before.Mode().IsRegular() {
			return fmt.Errorf("file changed during publish: %s", name)
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		if !info.Mode().IsRegular() || !os.SameFile(before, info) {
			_ = f.Close()
			return fmt.Errorf("file changed during publish: %s", name)
		}
		total += info.Size()
		if total > MaxExpandedBytes {
			_ = f.Close()
			return fmt.Errorf("site exceeds publish limits")
		}
		err = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg})
		if err == nil {
			_, err = io.CopyN(tw, f, info.Size())
		}
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return zw.Close()
}

// Extract accepts only bounded, regular-file archives. dir must be a new private directory.
func Extract(src io.Reader, dir string) error {
	return ExtractWithLimit(src, dir, MaxExpandedBytes)
}

// ExtractWithLimit enforces a total extracted byte limit across all entries.
func ExtractWithLimit(src io.Reader, dir string, maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("extracted size limit must be positive")
	}
	zr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("invalid gzip archive: %w", err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(zr)
	var total int64
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if err := ValidatePath(name); err != nil {
			return err
		}
		count++
		if h.Size < 0 || count > MaxFiles {
			return fmt.Errorf("site exceeds publish limits")
		}
		if h.Size > maxBytes-total {
			return fmt.Errorf("%w (%d bytes)", ErrSiteTooLarge, maxBytes)
		}
		total += h.Size
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return fmt.Errorf("archive links and special files are forbidden: %s", name)
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(name)), 0700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(path.Dir(name))), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(dir, filepath.FromSlash(name)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(f, tr, h.Size)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	// Consume the gzip trailer to verify its checksum, bounding trailing padding.
	n, err := io.Copy(io.Discard, io.LimitReader(zr, 1<<20))
	if err != nil {
		return err
	}
	if n == 1<<20 {
		return fmt.Errorf("excessive archive padding")
	}
	info, err := os.Stat(filepath.Join(dir, "index.html"))
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("publish requires a root index.html")
	}
	return nil
}
