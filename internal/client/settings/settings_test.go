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
