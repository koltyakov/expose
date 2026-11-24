package selfupdate

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
)

// Byte-slice forms of the streaming update steps, kept for the tests.

func download(ctx context.Context, url string) ([]byte, error) {
	return downloadLimited(ctx, url, maxDownloadBytes)
}

func extractBinary(assetName string, data []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := extractBinaryTo(assetName, bytes.NewReader(data), int64(len(data)), &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func extractFromTarGz(data []byte, name string) ([]byte, error) {
	var out bytes.Buffer
	if err := extractFromTarGzTo(bytes.NewReader(data), name, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func validateBinary(binary []byte) error {
	info, err := buildinfo.Read(bytes.NewReader(binary))
	if err != nil {
		return fmt.Errorf("read Go executable: %w", err)
	}
	return validateBuildInfo(info)
}

func replaceBinaryAtContext(ctx context.Context, exe string, binary []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	work, err := newUpdateDir(exe)
	if err != nil {
		return err
	}
	staged := filepath.Join(work, "expose.exe")
	defer func() {
		_ = os.Remove(staged)
		_ = os.Remove(work)
	}()
	if err := os.WriteFile(staged, binary, 0o600); err != nil {
		return err
	}
	return installStagedBinary(ctx, exe, staged)
}
