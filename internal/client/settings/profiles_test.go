package settings

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProfilesPreserveLegacyDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if err := os.MkdirAll(filepath.Dir(Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"server":"https://default.example.com","apiKey":"default-key"}`)
	if err := os.WriteFile(Path(), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	work := Credentials{ServerURL: "https://work.example.com", APIKey: "work-key"}
	other := Credentials{ServerURL: "https://other.example.com", APIKey: "other-key"}
	if err := SaveProfile("work", work); err != nil {
		t.Fatal(err)
	}
	if err := SaveProfile("other", other); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(Path())
	if err != nil || string(raw) != string(legacy) {
		t.Fatalf("default changed: %s, error %v", raw, err)
	}
	for profile, want := range map[string]Credentials{
		"":        {ServerURL: "https://default.example.com", APIKey: "default-key"},
		"default": {ServerURL: "https://default.example.com", APIKey: "default-key"},
		"work":    work,
		"other":   other,
	} {
		got, warning, err := LoadProfileChecked(profile)
		if err != nil || warning != "" || got != want {
			t.Fatalf("profile %q: got %#v, warning %q, error %v", profile, got, warning, err)
		}
	}
	updated := Credentials{ServerURL: "https://new.example.com", APIKey: "new-key"}
	if err := SaveProfile("work", updated); err != nil {
		t.Fatal(err)
	}
	if err := Save(Credentials{ServerURL: "https://default2.example.com", APIKey: "default2-key"}); err != nil {
		t.Fatal(err)
	}
	for profile, want := range map[string]Credentials{"work": updated, "other": other} {
		got, _, err := LoadProfileChecked(profile)
		if err != nil || got != want {
			t.Fatalf("profile %q after update: got %#v, error %v", profile, got, err)
		}
	}
}

func TestProfileNames(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{"", "default", "work", "work-2", "1_work", "con", strings.Repeat("a", 64)} {
		if _, err := ProfilePath(profile); err != nil {
			t.Errorf("valid profile %q: %v", profile, err)
		}
	}
	for _, profile := range []string{"../work", "a/b", `a\b`, "/work", "..", " ", "work ", "Work", "_work", "-work", "wörk", strings.Repeat("a", 65)} {
		if _, err := ProfilePath(profile); err == nil {
			t.Errorf("accepted invalid profile %q", profile)
		}
		if err := SaveProfile(profile, Credentials{ServerURL: "https://example.com", APIKey: "key"}); err == nil {
			t.Errorf("saved invalid profile %q", profile)
		}
		if _, _, err := LoadProfileChecked(profile); err == nil {
			t.Errorf("loaded invalid profile %q", profile)
		}
	}
}

func TestProfileMissingDoesNotFallBack(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	if err := Save(Credentials{ServerURL: "https://default.example.com", APIKey: "default-key"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadProfileChecked("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing profile: %v", err)
	}
}

func TestProfilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions do not apply on Windows")
	}
	t.Setenv("HOME", t.TempDir())
	creds := Credentials{ServerURL: "https://work.example.com", APIKey: "key"}
	if err := SaveProfile("work", creds); err != nil {
		t.Fatal(err)
	}
	path, err := ProfilePath("work")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("profile permissions: %v, %v", info, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, warning, err := LoadProfileChecked("work"); err != nil || warning == "" {
		t.Fatalf("permission warning: %q, error %v", warning, err)
	}
	if err := SaveProfile("work", creds); err != nil {
		t.Fatal(err)
	}
	if _, warning, err := LoadProfileChecked("work"); err != nil || warning != "" {
		t.Fatalf("secure replacement: %q, error %v", warning, err)
	}
}
