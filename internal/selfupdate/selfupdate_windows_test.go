package selfupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Hold the old process until the replacement has actually inspected its live
// process handle. This makes waiting observable rather than relying on timing.
func prepareRestartParent() (func() error, error) {
	name := fmt.Sprintf("Local\\expose-restart-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	event, err := windows.CreateEvent(nil, 0, 0, wide)
	if err != nil {
		return nil, err
	}
	if err = os.Setenv("EXPOSE_TEST_RESTART_EVENT", name); err != nil {
		_ = windows.CloseHandle(event)
		return nil, err
	}
	return func() error {
		defer func() { _ = windows.CloseHandle(event) }()
		status, err := windows.WaitForSingleObject(event, 10000)
		if err != nil || status != windows.WAIT_OBJECT_0 {
			return fmt.Errorf("replacement did not observe its live parent: status=%d, error=%v", status, err)
		}
		// Give an incorrectly non-waiting replacement time to attempt startup.
		time.Sleep(200 * time.Millisecond)
		return nil
	}, nil
}

func observeRestartParent(args []string) (func() error, error) {
	if len(args) < 4 || args[0] != restartCommand {
		return func() error { return nil }, nil
	}
	value, err := strconv.ParseUint(args[1], 10, strconv.IntSize)
	if err != nil {
		return nil, err
	}
	var parent windows.Handle
	if err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(value), windows.CurrentProcess(), &parent, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	status, err := windows.WaitForSingleObject(parent, 0)
	if err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		_ = windows.CloseHandle(parent)
		return nil, fmt.Errorf("expected live parent before handoff: status=%d, error=%v", status, err)
	}
	fmt.Printf("child %d: parent %s is alive before ResumeRestart, WAIT_TIMEOUT=%d\n", os.Getpid(), args[2], status)
	name, err := windows.UTF16PtrFromString(os.Getenv("EXPOSE_TEST_RESTART_EVENT"))
	if err != nil {
		_ = windows.CloseHandle(parent)
		return nil, err
	}
	event, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		_ = windows.CloseHandle(parent)
		return nil, err
	}
	err = windows.SetEvent(event)
	_ = windows.CloseHandle(event)
	if err != nil {
		_ = windows.CloseHandle(parent)
		return nil, err
	}
	return func() error {
		defer func() { _ = windows.CloseHandle(parent) }()
		status, err := windows.WaitForSingleObject(parent, 0)
		if err != nil || status != windows.WAIT_OBJECT_0 {
			return fmt.Errorf("replacement resumed before parent exit: status=%d, error=%v", status, err)
		}
		fmt.Printf("child %d: parent %s has exited after ResumeRestart, WAIT_OBJECT_0=%d\n", os.Getpid(), args[2], status)
		return nil
	}, nil
}

func assertRestartPID(t *testing.T, current, previous int) {
	t.Helper()
	if current == previous {
		t.Fatal("Windows restart did not start a replacement process")
	}
}

func TestResumeRestartRejectsInvalidHandoff(t *testing.T) {
	for _, args := range [][]string{
		{restartCommand},
		{restartCommand, "0", "1", ""},
		{restartCommand, "not-a-handle", "1", ""},
		{restartCommand, "1", "1", ""},
	} {
		if _, err := ResumeRestart(args); err == nil {
			t.Fatalf("accepted invalid handoff %v", args)
		}
	}
}

// A handle on the staged binary that does not share delete access makes the
// staged -> exe rename fail with a sharing violation after exe has already
// moved to previous.exe. installBinary must move the original back.
func TestInstallBinaryRestoresOriginalWhenInstallRenameFails(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "expose.exe")
	if err := os.WriteFile(exe, []byte("original"), 0o700); err != nil {
		t.Fatal(err)
	}
	update, err := os.MkdirTemp(dir, updateDirPrefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(update, "expose.exe")
	if err = os.WriteFile(staged, []byte("replacement"), 0o700); err != nil {
		t.Fatal(err)
	}

	stagedName, err := windows.UTF16PtrFromString(staged)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := windows.CreateFile(stagedName, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(hold) }()

	previousExecutable.Lock()
	before := previousExecutable.path
	previousExecutable.Unlock()

	if err = installBinary(staged, exe); err == nil {
		t.Fatal("expected install rename to fail while staged binary is held without delete sharing")
	}
	// Permission copy opens the staged file for WRITE_DAC only, which share
	// modes do not restrict; the failure must come from the second rename.
	if msg := err.Error(); !strings.HasPrefix(msg, "install executable:") || strings.Contains(msg, "restore failed") {
		t.Fatalf("expected a restored install-rename failure, got %v", err)
	}
	got, readErr := os.ReadFile(exe)
	if readErr != nil {
		t.Fatalf("original executable was not restored (install error: %v): %v", err, readErr)
	}
	if string(got) != "original" {
		t.Fatalf("restored executable has unexpected contents %q", got)
	}
	if _, statErr := os.Stat(filepath.Join(update, "previous.exe")); !os.IsNotExist(statErr) {
		t.Fatalf("previous.exe should not remain after restore: %v", statErr)
	}
	if _, statErr := os.Stat(staged); statErr != nil {
		t.Fatalf("staged binary should be left in the update directory: %v", statErr)
	}
	previousExecutable.Lock()
	recorded := previousExecutable.path
	previousExecutable.Unlock()
	if recorded != before {
		t.Fatalf("failed install changed previous executable from %q to %q", before, recorded)
	}
}

func TestCleanupPreviousConfinedToUpdateDirectory(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "expose.exe")
	keep := filepath.Join(dir, "previous.exe")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPrevious(exe, keep); err == nil {
		t.Fatal("accepted a path outside an update directory")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("removed unrelated file")
	}
	update, err := os.MkdirTemp(dir, ".expose-update-*")
	if err != nil {
		t.Fatal(err)
	}
	previous := filepath.Join(update, "previous.exe")
	if err = os.WriteFile(previous, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = cleanupPrevious(exe, previous); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(update); !os.IsNotExist(err) {
		t.Fatalf("update directory still exists: %v", err)
	}
}
