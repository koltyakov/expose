// Package settings persists and loads client credentials (server URL
// and API key) in a JSON file under the user's home directory.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Credentials contains the persisted client credentials.
type Credentials struct {
	ServerURL string `json:"server"`
	APIKey    string `json:"apiKey"`
}

// Path returns the absolute path to the settings file.
// It uses the user's home directory so credentials survive temp-dir cleanup.
func Path() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, ".expose", "settings.json")
}

// ProfilePath returns the settings path for a profile. Empty and "default"
// select the original settings file, so existing logins need no migration.
func ProfilePath(profile string) (string, error) {
	if profile == "" || profile == "default" {
		return Path(), nil
	}
	if len(profile) > 64 {
		return "", errors.New("profile name must be at most 64 characters")
	}
	for i, c := range profile {
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '-' && c != '_') {
			return "", errors.New("profile name must start with a lowercase letter or digit and contain only lowercase letters, digits, hyphens, or underscores")
		}
	}
	// The prefix also avoids reserved Windows filenames such as CON.json.
	return filepath.Join(filepath.Dir(Path()), "profiles", "profile-"+profile+".json"), nil
}

// Load reads and validates the settings file. Returns an error if the file
// is missing or contains empty credentials.
func Load() (Credentials, error) {
	creds, _, err := LoadChecked()
	return creds, err
}

// LoadChecked behaves like Load but additionally reports a non-empty warning
// when the settings file permissions are broader than 0600. The permission
// check is skipped on Windows where POSIX mode bits do not apply.
func LoadChecked() (Credentials, string, error) {
	return LoadProfileChecked("")
}

// LoadProfileChecked loads only the selected profile, never falling back to
// another profile, and reports insecure file permissions like LoadChecked.
func LoadProfileChecked(profile string) (Credentials, string, error) {
	path, err := ProfilePath(profile)
	if err != nil {
		return Credentials{}, "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, "", err
	}
	warning := permissionWarning(path)
	var s Credentials
	if err := json.Unmarshal(raw, &s); err != nil {
		return Credentials{}, "", err
	}
	s.ServerURL = strings.TrimSpace(s.ServerURL)
	s.APIKey = strings.TrimSpace(s.APIKey)
	if s.ServerURL == "" || s.APIKey == "" {
		return Credentials{}, "", errors.New("settings file is missing `server` or `apiKey`")
	}
	return s, warning, nil
}

func permissionWarning(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("settings file %s is readable by other users (permissions %04o); run `chmod 600 %s`", path, perm, path)
}

// Save writes validated credentials to the settings file with 0600 permissions.
func Save(s Credentials) error {
	return SaveProfile("", s)
}

// SaveProfile writes credentials for one profile without changing any others.
func SaveProfile(profile string, s Credentials) error {
	path, err := ProfilePath(profile)
	if err != nil {
		return err
	}
	s.ServerURL = strings.TrimSpace(s.ServerURL)
	s.APIKey = strings.TrimSpace(s.APIKey)
	if s.ServerURL == "" || s.APIKey == "" {
		return errors.New("`server` and `apiKey` are required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
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
	return replaceFile(tmpPath, path)
}
