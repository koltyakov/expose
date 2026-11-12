package selfupdate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Stage on the destination filesystem. Never unlink the installed executable
// or fall back to copying bytes into its live path.
func replaceBinaryAtContext(ctx context.Context, exe string, binary []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(exe)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("executable is not a regular file: %s", exe)
	}
	caps := getFileCaps(exe)
	dir, err := os.MkdirTemp(filepath.Dir(exe), ".expose-update-*")
	if err != nil {
		return fmt.Errorf("create update directory beside executable (directory must be writable): %w", err)
	}
	defer func() { _ = os.Remove(dir) }()
	staged := filepath.Join(dir, "expose.exe")
	defer func() { _ = os.Remove(staged) }()
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err = f.Write(binary); err != nil {
		return err
	}
	if err = f.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = installBinary(staged, exe); err != nil {
		return err
	}
	setFileCaps(exe, caps)
	if err = syncDir(filepath.Dir(exe)); err != nil {
		return fmt.Errorf("binary replaced, but syncing executable directory failed: %w", err)
	}
	return nil
}

// Linux file capabilities are best-effort. AmbientCapabilities in systemd
// avoids binding privileges to an executable that updates replace.
func getFileCaps(path string) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	out, err := exec.Command("getcap", path).Output()
	if err != nil {
		return ""
	}
	if _, after, ok := strings.Cut(strings.TrimSpace(string(out)), " "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func setFileCaps(path, caps string) {
	if caps != "" && runtime.GOOS == "linux" {
		_ = exec.Command("setcap", caps, path).Run()
	}
}
