package settings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPathUsesHomeDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := Path()
	want := filepath.Join(home, ".expose", "settings.json")
	if got != want {
		t.Fatalf("Path() = %q, want %q", got, want)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	input := Credentials{
		ServerURL: " https://example.com ",
		APIKey:    " secret-key ",
	}
	if err := Save(input); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	info, err := os.Stat(Path())
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", Path(), err)
	}
	if perms := info.Mode().Perm(); perms != 0o600 {
		t.Fatalf("settings file perms = %o, want 600", perms)
	}

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
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want not-exist error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() error = %v, want os.ErrNotExist", err)
	}
}

func TestLoadRejectsMissingCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

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
	home := t.TempDir()
	t.Setenv("HOME", home)

	err := Save(Credentials{ServerURL: " ", APIKey: " "})
	if err == nil {
		t.Fatal("Save() error = nil, want validation error")
	}
}

func TestSaveReplacesPermissiveFileWithSecurePermissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := Save(Credentials{ServerURL: "https://example.com", APIKey: "secret"}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("settings file perms = %o, want 600", got)
	}
}

func TestSaveReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
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
