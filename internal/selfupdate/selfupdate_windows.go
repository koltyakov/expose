package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

const restartCommand = "__selfupdate-restart"

var previousExecutable struct {
	sync.Mutex
	path string
}

func lockExecutable(exe string) (*os.File, error) {
	f, err := os.OpenFile(exe+".update.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open update lock: %w", err)
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock executable, another update may be running: %w", err)
	}
	return f, nil
}

func installBinary(staged, exe string) error {
	// Preserve access grants, including accounts explicitly allowed to run the
	// installed executable. Temporary files otherwise inherit different ACLs.
	sd, err := windows.GetNamedSecurityInfo(exe, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read executable permissions: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetNamedSecurityInfo(staged, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("preserve executable permissions: %w", err)
	}
	previous := filepath.Join(filepath.Dir(staged), "previous.exe")
	if err = os.Rename(exe, previous); err != nil {
		return fmt.Errorf("move old executable: %w", err)
	}
	if err = os.Rename(staged, exe); err != nil {
		if restoreErr := os.Rename(previous, exe); restoreErr != nil {
			return fmt.Errorf("install executable: %w; restore failed: %v; old binary remains at %s", err, restoreErr, previous)
		}
		return fmt.Errorf("install executable: %w", err)
	}
	if err = os.Remove(previous); err != nil {
		// A running Windows image may be renamed but not deleted. The replacement
		// process cleans it up after waiting for this process to exit.
		previousExecutable.Lock()
		previousExecutable.path = previous
		previousExecutable.Unlock()
	}
	return nil
}

func syncDir(string) error { return nil }

func restartExecutable(exe string, args, env []string) error {
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, true, uint32(os.Getpid()))
	if err != nil {
		return fmt.Errorf("open restart parent: %w", err)
	}
	defer func() { _ = windows.CloseHandle(parent) }()
	previousExecutable.Lock()
	previous := previousExecutable.path
	previousExecutable.Unlock()
	handoff := []string{restartCommand, strconv.FormatUint(uint64(parent), 10), strconv.Itoa(os.Getpid()), previous}
	cmd := exec.Command(exe, append(handoff, args[1:]...)...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(parent)}}
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("start replacement: %w", err)
	}
	return cmd.Process.Release()
}

// ResumeRestart runs only in the replacement process. Waiting on an inherited
// process handle avoids PID reuse and prevents overlap with the old service.
// After the handoff this same process runs expose; no helper stays resident.
func ResumeRestart(args []string) ([]string, error) {
	if len(args) == 0 || args[0] != restartCommand {
		return args, nil
	}
	if len(args) < 4 {
		return nil, errors.New("incomplete restart handoff")
	}
	value, err := strconv.ParseUint(args[1], 10, strconv.IntSize)
	if err != nil || value == 0 {
		return nil, errors.New("invalid restart process handle")
	}
	parent := windows.Handle(value)
	defer func() { _ = windows.CloseHandle(parent) }()
	pid, err := windows.GetProcessId(parent)
	if err != nil || strconv.FormatUint(uint64(pid), 10) != args[2] || pid == uint32(os.Getpid()) {
		return nil, errors.New("invalid restart parent")
	}
	status, err := windows.WaitForSingleObject(parent, 30000)
	if err != nil {
		return nil, fmt.Errorf("wait for restart parent: %w", err)
	}
	if status != windows.WAIT_OBJECT_0 {
		return nil, errors.New("restart parent did not exit within 30 seconds")
	}
	exe, err := executablePath()
	if err != nil {
		return nil, err
	}
	if args[3] != "" {
		if err = cleanupPrevious(exe, args[3]); err != nil {
			return nil, err
		}
	}
	// Future updates must restart the original command, not replay this handoff
	// with an already-closed process handle.
	original := args[4:]
	os.Args = append([]string{exe}, original...)
	return original, nil
}

func cleanupPrevious(exe, previous string) error {
	dir := filepath.Dir(previous)
	if filepath.Base(previous) != "previous.exe" || !strings.HasPrefix(filepath.Base(dir), ".expose-update-") ||
		!strings.EqualFold(filepath.Dir(dir), filepath.Dir(exe)) {
		return errors.New("invalid previous executable path")
	}
	// Do not follow an update directory replaced with a symlink or junction.
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	// Antivirus or another running invocation can retain the old image. Failed
	// cleanup must not stop the new version from starting.
	_ = os.Remove(previous)
	_ = os.Remove(dir)
	return nil
}
