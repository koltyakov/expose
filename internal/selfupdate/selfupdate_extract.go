package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// extractBinaryFile streams the "expose" (or "expose.exe") binary out of the
// downloaded archive at archivePath into a new file at dst.
func extractBinaryFile(assetName, archivePath, dst string) error {
	src, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	extractErr := extractBinaryTo(assetName, src, info.Size(), out)
	return errors.Join(extractErr, out.Close())
}

func extractBinaryTo(assetName string, src io.ReaderAt, size int64, dst io.Writer) error {
	if strings.HasSuffix(assetName, ".zip") {
		return extractFromZipTo(src, size, "expose.exe", dst)
	}
	return extractFromTarGzTo(io.NewSectionReader(src, 0, size), "expose", dst)
}

func extractFromTarGzTo(src io.Reader, name string, dst io.Writer) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == name && hdr.Typeflag == tar.TypeReg {
			return copyWithLimit(dst, tr, maxBinaryBytes)
		}
	}
	return fmt.Errorf("binary %q not found in archive", name)
}

func extractFromZipTo(src io.ReaderAt, size int64, name string, dst io.Writer) error {
	zr, err := zip.NewReader(src, size)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == name {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer func() { _ = rc.Close() }()
			return copyWithLimit(dst, rc, maxBinaryBytes)
		}
	}
	return fmt.Errorf("binary %q not found in archive", name)
}

func copyWithLimit(dst io.Writer, src io.Reader, limit int64) error {
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("content exceeds limit of %d bytes", limit)
	}
	return nil
}
