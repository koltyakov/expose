// Package publish implements the archive format and file policy for hosted sites.
package publish

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/koltyakov/expose/internal/domain"
)

// Allow 200 MiB sites even when compression adds archive overhead.
const MaxArchiveBytes int64 = 256 << 20
const MaxExpandedBytes int64 = 500 << 20
const MaxFiles = 20000

var ErrSiteTooLarge = errors.New("site exceeds maximum extracted size")

// ValidatePath rejects unsafe names and private file paths.
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

// Archive writes a gzip-compressed tar archive, omitting blocked paths.
func Archive(dir string, dst io.Writer) error {
	return ArchiveWithWarnings(dir, dst, nil)
}

// ArchiveWithWarnings reports each omitted path through warn, when non-nil.
// Blocked directories are reported once and their contents are skipped.
func ArchiveWithWarnings(dir string, dst io.Writer, warn func(string, error)) error {
	return archive(dir, dst, warn, nil, nil, nil, nil)
}

// ArchiveProgress describes the regular files included in an archive.
type ArchiveProgress struct {
	Files, TotalFiles int
	Bytes, TotalBytes int64
}

// ArchiveWithProgress omits blocked paths silently and reports file and byte progress.
func ArchiveWithProgress(dir string, dst io.Writer, report func(ArchiveProgress)) error {
	return archive(dir, dst, nil, report, nil, nil, nil)
}

// ArchiveDelta writes a target manifest and only new or changed file contents.
// Files absent from the target manifest are removed when the server commits it.
func ArchiveDelta(dir string, dst io.Writer, local, remote []domain.PublishedFile, report func(ArchiveProgress)) error {
	return ArchiveDeltaWithIgnoredEmptyFiles(dir, dst, local, remote, nil, report)
}

// ArchiveDeltaWithIgnoredEmptyFiles allows explicitly omitted editor placeholders.
// An ignored file that gains content before archiving requires a fresh comparison.
func ArchiveDeltaWithIgnoredEmptyFiles(dir string, dst io.Writer, local, remote []domain.PublishedFile, ignored []string, report func(ArchiveProgress)) error {
	diff, err := DiffFiles(local, remote)
	if err != nil {
		return err
	}
	changed := make(map[string]bool, len(diff.Changed))
	for _, file := range diff.Changed {
		changed[file.Path] = true
	}
	ignoredEmpty := make(map[string]bool, len(ignored))
	for _, name := range ignored {
		ignoredEmpty[name] = true
	}
	return archive(dir, dst, nil, report, local, changed, ignoredEmpty)
}

func openArchiveRoot(dir string) (*os.Root, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := ValidatePath(filepath.Base(abs)); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}

func scanArchiveFiles(root *os.Root, warn func(string, error)) ([]string, int64, error) {
	return scanPublicFiles(root, warn, MaxExpandedBytes)
}

func scanPublicFiles(root *os.Root, warn func(string, error), maxBytes int64) ([]string, int64, error) {
	var names []string
	var total int64
	err := fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if err := ValidatePath(name); err != nil {
			if warn != nil {
				warn(name, err)
			}
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
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
		if (maxBytes > 0 && total > maxBytes) || len(names) > MaxFiles {
			return fmt.Errorf("site exceeds publish limits")
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	index, err := root.Stat("index.html")
	if err != nil || !index.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("publish requires a root index.html")
	}
	return names, total, nil
}

func archive(dir string, dst io.Writer, warn func(string, error), report func(ArchiveProgress), manifest []domain.PublishedFile, changed, ignoredEmpty map[string]bool) error {
	root, err := openArchiveRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	names, total, err := scanArchiveFiles(root, warn)
	if err != nil {
		return err
	}
	expected := make(map[string]domain.PublishedFile, len(manifest))
	if manifest != nil {
		for _, file := range manifest {
			expected[file.Path] = file
		}
		if len(ignoredEmpty) > 0 {
			included := names[:0]
			for _, name := range names {
				if ignoredEmpty[name] {
					info, err := root.Lstat(name)
					if err != nil {
						return err
					}
					if !info.Mode().IsRegular() || info.Size() != 0 {
						return fmt.Errorf("file changed during publish: %s", name)
					}
					continue
				}
				included = append(included, name)
			}
			names = included
		}
		if len(names) != len(manifest) {
			return fmt.Errorf("folder changed during publish; retry")
		}
		selected := make([]string, 0, len(changed))
		total = 0
		for _, name := range names {
			file, exists := expected[name]
			if !exists {
				return fmt.Errorf("folder changed during publish; retry")
			}
			if changed[name] {
				selected = append(selected, name)
				total += file.Size
			}
		}
		names = selected
	}
	progress := ArchiveProgress{TotalFiles: len(names), TotalBytes: total}
	if report != nil {
		report(progress)
	}
	zw := gzip.NewWriter(dst)
	tw := tar.NewWriter(zw)
	if manifest != nil {
		metadata, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		if len(metadata) > MaxManifestBytes {
			return fmt.Errorf("file manifest exceeds %d MiB", MaxManifestBytes>>20)
		}
		if err := tw.WriteHeader(&tar.Header{Name: deltaManifestName, Mode: 0600, Size: int64(len(metadata)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(metadata); err != nil {
			return err
		}
	}
	var contents io.Writer = tw
	if report != nil {
		contents = &archiveProgressWriter{w: tw, progress: &progress, report: report}
	}
	total = 0
	for _, name := range names {
		f, info, err := openRegularFile(root, name)
		if err != nil {
			return err
		}
		if manifest != nil && info.Size() != expected[name].Size {
			_ = f.Close()
			return fmt.Errorf("file changed during publish: %s", name)
		}
		total += info.Size()
		if total > MaxExpandedBytes {
			_ = f.Close()
			return fmt.Errorf("site exceeds publish limits")
		}
		err = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: info.Size(), ModTime: info.ModTime(), Typeflag: tar.TypeReg})
		h := sha256.New()
		if err == nil {
			writer := contents
			if manifest != nil {
				writer = io.MultiWriter(contents, h)
			}
			_, err = io.CopyN(writer, f, info.Size())
		}
		_ = f.Close()
		if err != nil {
			return err
		}
		if manifest != nil && hex.EncodeToString(h.Sum(nil)) != expected[name].Checksum {
			return fmt.Errorf("file changed during publish: %s", name)
		}
		progress.Files++
		if report != nil {
			report(progress)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return zw.Close()
}

type archiveProgressWriter struct {
	w        io.Writer
	progress *ArchiveProgress
	report   func(ArchiveProgress)
}

func (w *archiveProgressWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.progress.Bytes += int64(n)
	w.report(*w.progress)
	return n, err
}

// Extract accepts only bounded, regular-file archives. dir must be a new private directory.
func Extract(src io.Reader, dir string) error {
	return ExtractWithLimit(src, dir, MaxExpandedBytes)
}

// ExtractWithLimit enforces a total extracted byte limit across all entries.
func ExtractWithLimit(src io.Reader, dir string, maxBytes int64) error {
	_, err := extractArchive(src, dir, maxBytes, false)
	return err
}

// ExtractDeltaWithLimit validates the target manifest and extracts changed files
// into a new private directory. CompleteDelta must run before publishing it.
func ExtractDeltaWithLimit(src io.Reader, dir string, maxBytes int64) ([]domain.PublishedFile, error) {
	return extractArchive(src, dir, maxBytes, true)
}

func extractArchive(src io.Reader, dir string, maxBytes int64, delta bool) ([]domain.PublishedFile, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("extracted size limit must be positive")
	}
	zr, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("invalid gzip archive: %w", err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(zr)
	var manifest []domain.PublishedFile
	var expected map[string]domain.PublishedFile
	if delta {
		header, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("missing incremental manifest: %w", err)
		}
		if header.Name != deltaManifestName || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > MaxManifestBytes {
			return nil, fmt.Errorf("invalid incremental manifest header")
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return nil, fmt.Errorf("invalid incremental manifest: %w", err)
		}
		if err := validateManifest(manifest, maxBytes, true); err != nil {
			return nil, err
		}
		expected = make(map[string]domain.PublishedFile, len(manifest))
		for _, file := range manifest {
			expected[file.Path] = file
		}
	}
	if err := extractTar(tr, dir, maxBytes, expected); err != nil {
		return nil, err
	}
	// Consume the gzip trailer to verify its checksum, bounding trailing padding.
	n, err := io.Copy(io.Discard, io.LimitReader(zr, 1<<20))
	if err != nil {
		return nil, err
	}
	if n == 1<<20 {
		return nil, fmt.Errorf("excessive archive padding")
	}
	if !delta {
		info, err := os.Stat(filepath.Join(dir, "index.html"))
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("publish requires a root index.html")
		}
	}
	return manifest, nil
}

func extractTar(tr *tar.Reader, dir string, maxBytes int64, expected map[string]domain.PublishedFile) error {
	var total int64
	count := 0
	seen := make(map[string]bool)
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
		if seen[name] {
			return fmt.Errorf("duplicate archive path: %s", name)
		}
		seen[name] = true
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
		if expected != nil {
			file, exists := expected[name]
			if !exists || h.Typeflag != tar.TypeReg || h.Size != file.Size {
				return fmt.Errorf("archive entry does not match manifest: %s", name)
			}
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
		var contents io.Writer = f
		hash := sha256.New()
		if expected != nil {
			contents = io.MultiWriter(f, hash)
		}
		_, copyErr := io.CopyN(contents, tr, h.Size)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if expected != nil && hex.EncodeToString(hash.Sum(nil)) != expected[name].Checksum {
			return fmt.Errorf("checksum mismatch: %s", name)
		}
	}
	return nil
}
