package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// errorPrivilegeNotHeld is Windows ERROR_PRIVILEGE_NOT_HELD, returned by
// CreateSymbolicLink without SeCreateSymbolicLinkPrivilege or Developer Mode.
const errorPrivilegeNotHeld = syscall.Errno(1314)

// isolateHome points the OS home directory at a fresh temp dir and returns it.
// os.UserHomeDir reads USERPROFILE on Windows and HOME elsewhere, so both are
// set; the check fails fast instead of touching a real user profile.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if got, err := os.UserHomeDir(); err != nil || got != home {
		t.Fatalf("home isolation failed: UserHomeDir() = %q, %v; want %q", got, err, home)
	}
	return home
}

// assertOwnerOnlyPerms checks POSIX 0600 mode bits. Windows reports only the
// read-only attribute through Mode().Perm(), so there is nothing to check.
func assertOwnerOnlyPerms(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if perms := info.Mode().Perm(); perms != 0o600 {
		t.Fatalf("%s perms = %o, want 600", path, perms)
	}
}

// symlinkOrSkip skips only when Windows denies symlink creation for lack of
// privilege; any other failure is a real test failure.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld) {
		t.Skipf("symlink creation requires SeCreateSymbolicLinkPrivilege or Developer Mode: %v", err)
	}
	t.Fatalf("Symlink() error = %v", err)
}

func TestPathUsesHomeDirectory(t *testing.T) {
	home := isolateHome(t)

	got := Path()
	want := filepath.Join(home, ".expose", "settings.json")
	if got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	isolateHome(t)

	input := Credentials{
		ServerURL: " https://example.com ",
		APIKey:    " secret-key ",
	}
	if err := Save(input); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	assertOwnerOnlyPerms(t, Path())

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := Credentials{
		ServerURL: "https://example.com",
		APIKey:    "secret-key",
	}
	if got != want {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoadMissingFileReturnsError(t *testing.T) {
	isolateHome(t)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want not-exist error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() error = %v, want os.ErrNotExist", err)
	}
}

func TestLoadRejectsMissingCredentials(t *testing.T) {
	isolateHome(t)

	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	raw, err := json.Marshal(Credentials{ServerURL: "https://example.com"})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = Load()
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestSaveRejectsEmptyCredentials(t *testing.T) {
	isolateHome(t)

	err := Save(Credentials{ServerURL: " ", APIKey: " "})
	if err == nil {
		t.Fatal("Save() error = nil, want validation error")
	}
}

func TestSaveReplacesPermissiveFileWithSecurePermissions(t *testing.T) {
	isolateHome(t)
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	want := Credentials{ServerURL: "https://example.com", APIKey: "secret"}
	if err := Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	// The existing file must be replaced on every OS, including via
	// MoveFileEx on Windows.
	if got, err := Load(); err != nil || got != want {
		t.Fatalf("Load() after replace = %#v, %v; want %#v", got, err, want)
	}
	assertOwnerOnlyPerms(t, path)
}

func TestLoadCheckedWarnsOnBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on windows")
	}
	isolateHome(t)

	if err := Save(Credentials{ServerURL: "https://example.com", APIKey: "secret"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := os.Chmod(Path(), 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	creds, warning, err := LoadChecked()
	if err != nil {
		t.Fatalf("LoadChecked() error = %v", err)
	}
	if creds.APIKey != "secret" {
		t.Fatalf("LoadChecked() APIKey = %q, want %q", creds.APIKey, "secret")
	}
	if warning == "" {
		t.Fatal("LoadChecked() warning = empty, want permission warning")
	}
	if !strings.Contains(warning, "0644") {
		t.Fatalf("LoadChecked() warning = %q, want it to mention the mode", warning)
	}

	if err := os.Chmod(Path(), 0o600); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	_, warning, err = LoadChecked()
	if err != nil {
		t.Fatalf("LoadChecked() error = %v", err)
	}
	if warning != "" {
		t.Fatalf("LoadChecked() warning = %q, want empty for 0600", warning)
	}
}

func TestSaveReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	isolateHome(t)
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	symlinkOrSkip(t, target, path)
	if err := Save(Credentials{ServerURL: "https://example.com", APIKey: "secret"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target) error = %v", err)
	}
	if got := string(raw); got != "unchanged" {
		t.Fatalf("target contents = %q, want unchanged", got)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("settings path remains a symlink")
	}
}
