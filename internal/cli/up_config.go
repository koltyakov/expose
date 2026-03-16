package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/config"
)

type upConfig struct {
	Version int
	Server  string
	APIKey  string
	Access  upAccessConfig
	Tunnels []upTunnelConfig
}

type upAccessConfig struct {
	Protect     bool
	User        string
	Password    string
	PasswordEnv string // deprecated alias for Password; accepted for compatibility
}

type upTunnelConfig struct {
	Name        string
	Subdomain   string
	Port        int
	Dir         string
	SPA         bool
	Folders     bool
	PathPrefix  string
	StripPrefix bool
}

func loadUpConfigFile(path string) (upConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return upConfig{}, err
	}
	cfg, err := parseUpYAML(string(b))
	if err != nil {
		return upConfig{}, err
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		return upConfig{}, err
	}
	return cfg, nil
}

func writeUpConfigFile(path string, cfg upConfig) error {
	if err := cfg.normalizeAndValidate(); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(renderUpYAML(cfg)), 0o644)
}

func (c *upConfig) normalizeAndValidate() error {
	if c == nil {
		return errors.New("missing config")
	}
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d (expected 1)", c.Version)
	}

	c.Server = strings.TrimSpace(c.Server)
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.Access.User = strings.TrimSpace(c.Access.User)
	c.Access.Password = strings.TrimSpace(c.Access.Password)
	c.Access.PasswordEnv = strings.TrimSpace(c.Access.PasswordEnv)
	if c.Access.Password == "" && c.Access.PasswordEnv != "" {
		c.Access.Password = c.Access.PasswordEnv
		c.Access.PasswordEnv = ""
	}
	if c.Access.User == "" {
		c.Access.User = "admin"
	}
	if c.Access.Password != "" && c.Access.PasswordEnv != "" {
		return errors.New("protect.password and protect.password_env are mutually exclusive")
	}
	if c.Access.Password != "" {
		c.Access.Protect = true
	}

	if len(c.Tunnels) == 0 {
		return errors.New("config must define at least one tunnel")
	}

	seenNames := map[string]struct{}{}
	seenRoutes := map[string]struct{}{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		t.Name = strings.TrimSpace(t.Name)
		t.Subdomain = normalizeUpSubdomain(t.Subdomain)
		t.Dir = strings.TrimSpace(t.Dir)
		if t.Name == "" {
			t.Name = t.Subdomain
			if t.Name == "" {
				t.Name = fmt.Sprintf("route-%d", i+1)
			}
		}
		if _, dup := seenNames[t.Name]; dup {
			return fmt.Errorf("duplicate tunnel name %q", t.Name)
		}
		seenNames[t.Name] = struct{}{}

		if t.Subdomain == "" {
			return fmt.Errorf("tunnels[%d].subdomain is required", i)
		}
		if err := config.ValidateTunnelSubdomain(t.Subdomain); err != nil {
			return fmt.Errorf("tunnels[%d].subdomain: %w", i, err)
		}
		switch {
		case t.Port != 0 && t.Dir != "":
			return fmt.Errorf("tunnels[%d] must set either port or dir, not both", i)
		case t.Port <= 0 && t.Dir == "":
			return fmt.Errorf("tunnels[%d] must set either port or dir", i)
		case t.Dir == "":
			if t.Port > 65535 {
				return fmt.Errorf("tunnels[%d].port must be between 1 and 65535", i)
			}
		case t.Port > 65535:
			return fmt.Errorf("tunnels[%d].port must be between 1 and 65535", i)
		}
		if t.Dir == "" {
			if t.SPA {
				return fmt.Errorf("tunnels[%d].spa requires dir", i)
			}
			if t.Folders {
				return fmt.Errorf("tunnels[%d].folders requires dir", i)
			}
		}
		prefix, err := normalizeUpPathPrefix(t.PathPrefix)
		if err != nil {
			return fmt.Errorf("tunnels[%d].path_prefix: %w", i, err)
		}
		t.PathPrefix = prefix

		key := t.Subdomain + "|" + t.PathPrefix
		if _, dup := seenRoutes[key]; dup {
			return fmt.Errorf("duplicate route for subdomain %q path_prefix %q", t.Subdomain, t.PathPrefix)
		}
		seenRoutes[key] = struct{}{}
	}

	return nil
}

func normalizeUpSubdomain(raw string) string {
	raw = config.NormalizeTunnelSubdomain(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimSuffix(raw, "/")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	return raw
}

func normalizeUpPathPrefix(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/", nil
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	if strings.Contains(raw, "//") {
		for strings.Contains(raw, "//") {
			raw = strings.ReplaceAll(raw, "//", "/")
		}
	}
	if raw != "/" {
		raw = strings.TrimSuffix(raw, "/")
	}
	if strings.ContainsAny(raw, "?#") {
		return "", errors.New("must not include query or fragment")
	}
	return raw, nil
}

func (t upTunnelConfig) IsStatic() bool {
	return strings.TrimSpace(t.Dir) != ""
}
