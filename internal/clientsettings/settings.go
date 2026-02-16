// Package clientsettings persists and loads client credentials (server URL
// and API key) in a JSON file under the user's cache directory.
package clientsettings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Settings contains the persisted client credentials.
type Settings struct {
	ServerURL string `json:"server_url"`
	APIKey    string `json:"api_key"`
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

// Load reads and validates the settings file. Returns an error if the file
// is missing or contains empty credentials.
func Load() (Settings, error) {
	path := Path()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return Settings{}, err
	}
	s.ServerURL = strings.TrimSpace(s.ServerURL)
	s.APIKey = strings.TrimSpace(s.APIKey)
	if s.ServerURL == "" || s.APIKey == "" {
		return Settings{}, errors.New("settings file is missing server_url or api_key")
	}
	return s, nil
}

// Save writes validated credentials to the settings file with 0600 permissions.
func Save(s Settings) error {
	s.ServerURL = strings.TrimSpace(s.ServerURL)
	s.APIKey = strings.TrimSpace(s.APIKey)
	if s.ServerURL == "" || s.APIKey == "" {
		return errors.New("server_url and api_key are required")
	}
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
