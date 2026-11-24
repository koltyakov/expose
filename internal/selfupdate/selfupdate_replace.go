package selfupdate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// updateDirPrefix names the work directories created beside the executable.
const updateDirPrefix = ".expose-update-"

// newUpdateDir creates a work directory on the executable's filesystem, so
// the staged binary can be renamed into place.
func newUpdateDir(exe string) (string, error) {
	dir, err := os.MkdirTemp(filepath.Dir(exe), updateDirPrefix+"*")
	if err != nil {
		return "", fmt.Errorf("create update directory beside executable (directory must be writable): %w", err)
	}
	return dir, nil
}

// installStagedBinary replaces exe with staged, a complete file inside an
// update directory beside exe. It never unlinks the installed executable or
// copies bytes into its live path.
func installStagedBinary(ctx context.Context, exe, staged string) error {
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
	f, err := os.OpenFile(staged, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
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

// staleUpdateDirAge protects a work directory another executable in the
// same folder may be using; those hold their own lock, not ours.
const staleUpdateDirAge = time.Hour

// sweepUpdateDirs removes update directories left beside exe by a process
// that stopped mid-update. The caller holds exe's update lock.
func sweepUpdateDirs(exe string, now time.Time) {
	entries, err := os.ReadDir(filepath.Dir(exe))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), updateDirPrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || now.Sub(info.ModTime()) < staleUpdateDirAge {
			continue
		}
		// Errors are expected for a directory whose previous.exe still runs
		// (Windows); a later sweep retries.
		_ = os.RemoveAll(filepath.Join(filepath.Dir(exe), entry.Name()))
	}
}

// SweepStaleUpdates removes update work directories left beside the running
// executable by an interrupted update. It skips the sweep while another
// update holds the lock.
func SweepStaleUpdates() {
	exe, err := executablePath()
	if err != nil {
		return
	}
	lock, err := lockExecutable(exe)
	if err != nil {
		return
	}
	defer func() { _ = lock.Close() }()
	sweepUpdateDirs(exe, time.Now())
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
