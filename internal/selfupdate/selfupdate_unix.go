//go:build !windows

package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func lockExecutable(exe string) (*os.File, error) {
	fd, err := unix.Open(exe+".update.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open update lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), exe+".update.lock")
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock executable, another update may be running: %w", err)
	}
	// Keep the lock file. Removing it could let another process lock a new inode.
	return f, nil
}

func installBinary(staged, exe string) error {
	return os.Rename(staged, exe)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err = dir.Sync(); errors.Is(err, syscall.EINVAL) {
		return nil
	}
	return err
}

func restartExecutable(exe string, args, env []string) error {
	return syscall.Exec(exe, args, env)
}

// ResumeRestart is a no-op on Unix, where restart preserves the process ID.
func ResumeRestart(args []string) ([]string, error) { return args, nil }
