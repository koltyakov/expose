package selfupdate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// replaceBinary atomically replaces the current executable with newBinary.
// It writes to a temp file next to the original, then renames.
func replaceBinary(newBinary []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determine executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}
	return replaceBinaryAt(exe, newBinary)
}

// replaceBinaryAt replaces the binary at the given path with newBinary.
// It first tries an atomic rename in the same directory, and falls back
// to an in-place overwrite when the directory is not writable.
func replaceBinaryAt(exe string, newBinary []byte) error {
	// On Linux, capture file capabilities (e.g. cap_net_bind_service)
	// before the replace so we can re-apply them to the new file.
	caps := getFileCaps(exe)

	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, "expose-update-*")
	if err != nil {
		// The binary directory may not be writable (e.g. /usr/local/bin when
		// running as a non-root systemd service). Fall back to the system
		// temp directory and use copy instead of rename.
		if isPermissionError(err) {
			return replaceBinaryCopy(exe, newBinary, caps)
		}
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // clean up on failure

	if _, err := tmp.Write(newBinary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Preserve the original file permissions.
	info, err := os.Stat(exe)
	if err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, info.Mode()); err != nil {
		return err
	}

	// On most systems we can rename over the running binary.
	if err := os.Rename(tmpPath, exe); err != nil {
		if shouldFallbackToCopy(err) {
			return replaceBinaryCopy(exe, newBinary, caps)
		}
		return fmt.Errorf("rename: %w", err)
	}

	// Re-apply Linux file capabilities after the rename.
	setFileCaps(exe, caps)

	if err := syncDir(dir); err != nil {
		return err
	}
	return nil
}

// replaceBinaryCopy replaces the executable when the binary's directory is not
// writable for creating temp files. It writes the new binary to the system temp
// directory, then removes the old binary and creates a fresh file at the same
// path. The remove-then-create avoids ETXTBSY on Linux (the kernel forbids
// writing to a running executable, but unlinking it and creating a new inode
// at the same path works).
func replaceBinaryCopy(exe string, newBinary []byte, caps string) error {
	// Preserve the original file permissions before removing.
	info, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("stat binary: %w", err)
	}
	mode := info.Mode()

	tmp, err := os.CreateTemp("", "expose-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(newBinary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	backupPath := fmt.Sprintf("%s.old.%d", exe, time.Now().UnixNano())
	swappedWithBackup := false
	if err := os.Rename(exe, backupPath); err == nil {
		swappedWithBackup = true
	} else {
		// If we cannot swap to a backup name, fall back to remove+create.
		// On Linux this unlinks the directory entry while the running process
		// keeps its file descriptor.
		if err := os.Remove(exe); err != nil {
			return fmt.Errorf("remove old binary (the binary must be in a directory writable by the service user, e.g. /opt/expose/bin/): %w", err)
		}
	}

	if err := copyFilePath(tmpPath, exe, mode); err != nil {
		if swappedWithBackup {
			if restoreErr := os.Rename(backupPath, exe); restoreErr != nil {
				return fmt.Errorf("create new binary: %w (restore old binary failed: %v)", err, restoreErr)
			}
		}
		return fmt.Errorf("create new binary: %w", err)
	}
	if swappedWithBackup {
		_ = os.Remove(backupPath)
	}

	// Re-apply Linux file capabilities.
	setFileCaps(exe, caps)

	if err := syncDir(filepath.Dir(exe)); err != nil {
		return err
	}
	return nil
}

func copyFilePath(srcPath, dstPath string, mode os.FileMode) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open temp file: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return nil
}

func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

// getFileCaps reads Linux file capabilities (e.g. "cap_net_bind_service=ep")
// from the given path using the getcap command. Returns an empty string on
// non-Linux systems or when getcap is unavailable.
func getFileCaps(path string) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	out, err := exec.Command("getcap", path).Output()
	if err != nil {
		return ""
	}
	// getcap output format: "/usr/local/bin/expose cap_net_bind_service=ep"
	line := strings.TrimSpace(string(out))
	if idx := strings.Index(line, " "); idx >= 0 {
		return strings.TrimSpace(line[idx+1:])
	}
	return ""
}

// setFileCaps re-applies previously captured Linux file capabilities.
// It is a best-effort operation - errors are silently ignored (the caller
// may not be root, in which case setcap will fail and the administrator
// must re-run setcap manually).
func setFileCaps(path, caps string) {
	if caps == "" || runtime.GOOS != "linux" {
		return
	}
	_ = exec.Command("setcap", caps, path).Run()
}

func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

func shouldFallbackToCopy(err error) bool {
	if err == nil {
		return false
	}
	if isPermissionError(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "text file busy") ||
		strings.Contains(msg, "cross-device link") ||
		strings.Contains(msg, "device or resource busy")
}
