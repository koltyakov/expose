package clientsettings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Settings struct {
	ServerURL string `json:"server_url"`
	APIKey    string `json:"api_key"`
}

func Path() string {
	return filepath.Join(os.TempDir(), ".expose", "settings.json")
}

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
