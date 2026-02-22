package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
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
		if strings.Contains(t.Subdomain, "/") || strings.Contains(t.Subdomain, "://") {
			return fmt.Errorf("tunnels[%d].subdomain must be a hostname label, not a URL", i)
		}
		if t.Port <= 0 || t.Port > 65535 {
			return fmt.Errorf("tunnels[%d].port must be between 1 and 65535", i)
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
	raw = strings.TrimSpace(strings.ToLower(raw))
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

func renderUpYAML(cfg upConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %d\n", cfg.Version)
	if cfg.Server != "" {
		fmt.Fprintf(&b, "server: %s\n", yamlQuoteString(cfg.Server))
	}
	if cfg.APIKey != "" {
		fmt.Fprintf(&b, "api_key: %s\n", yamlQuoteString(cfg.APIKey))
	}
	if cfg.Access.Protect || cfg.Access.User != "" || cfg.Access.Password != "" || cfg.Access.PasswordEnv != "" {
		b.WriteString("protect:\n")
		if cfg.Access.User != "" {
			fmt.Fprintf(&b, "  user: %s\n", yamlQuoteString(cfg.Access.User))
		}
		if cfg.Access.Password != "" {
			fmt.Fprintf(&b, "  password: %s\n", yamlQuoteString(cfg.Access.Password))
		} else if cfg.Access.PasswordEnv != "" {
			// Canonicalize legacy alias when writing.
			fmt.Fprintf(&b, "  password: %s\n", yamlQuoteString(cfg.Access.PasswordEnv))
		}
	}
	b.WriteString("tunnels:\n")
	for _, t := range cfg.Tunnels {
		b.WriteString("  - ")
		fmt.Fprintf(&b, "name: %s\n", yamlQuoteString(t.Name))
		fmt.Fprintf(&b, "    subdomain: %s\n", yamlQuoteString(t.Subdomain))
		fmt.Fprintf(&b, "    port: %d\n", t.Port)
		fmt.Fprintf(&b, "    path_prefix: %s\n", yamlQuoteString(t.PathPrefix))
		fmt.Fprintf(&b, "    strip_prefix: %t\n", t.StripPrefix)
	}
	return b.String()
}

func yamlQuoteString(v string) string {
	v = strings.ReplaceAll(v, "'", "''")
	return "'" + v + "'"
}

func parseUpYAML(raw string) (upConfig, error) {
	var cfg upConfig
	lines := strings.Split(raw, "\n")

	type sectionKind int
	const (
		sectionTop sectionKind = iota
		sectionProtect
		sectionTunnels
	)
	section := sectionTop
	currentTunnel := -1

	for i, rawLine := range lines {
		lineNo := i + 1
		line := strings.TrimRight(rawLine, " \r")
		if strings.ContainsRune(line, '\t') {
			return cfg, fmt.Errorf("line %d: tabs are not supported", lineNo)
		}
		line = stripYAMLComment(line)
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := countLeadingSpaces(line)
		trimmed := strings.TrimSpace(line)

		if indent == 0 {
			section = sectionTop
			currentTunnel = -1
			key, value, hasValue, ok := splitYAMLKeyValue(trimmed)
			if !ok {
				return cfg, fmt.Errorf("line %d: expected key: value", lineNo)
			}
			switch key {
			case "version":
				if !hasValue {
					return cfg, fmt.Errorf("line %d: version requires a value", lineNo)
				}
				n, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil {
					return cfg, fmt.Errorf("line %d: invalid version", lineNo)
				}
				cfg.Version = n
			case "server":
				if !hasValue {
					return cfg, fmt.Errorf("line %d: server requires a value", lineNo)
				}
				s, err := parseYAMLString(value)
				if err != nil {
					return cfg, fmt.Errorf("line %d: %w", lineNo, err)
				}
				cfg.Server = s
			case "api_key":
				if !hasValue {
					return cfg, fmt.Errorf("line %d: api_key requires a value", lineNo)
				}
				s, err := parseYAMLString(value)
				if err != nil {
					return cfg, fmt.Errorf("line %d: %w", lineNo, err)
				}
				cfg.APIKey = s
			case "protect", "access":
				if hasValue && strings.TrimSpace(value) != "" {
					return cfg, fmt.Errorf("line %d: %s must be a nested mapping", lineNo, key)
				}
				section = sectionProtect
			case "tunnels":
				if hasValue && strings.TrimSpace(value) != "" {
					return cfg, fmt.Errorf("line %d: tunnels must be a list", lineNo)
				}
				section = sectionTunnels
			default:
				return cfg, fmt.Errorf("line %d: unknown key %q", lineNo, key)
			}
			continue
		}

		switch section {
		case sectionProtect:
			if indent != 2 {
				return cfg, fmt.Errorf("line %d: protect fields must be indented by 2 spaces", lineNo)
			}
			key, value, hasValue, ok := splitYAMLKeyValue(trimmed)
			if !ok || !hasValue {
				return cfg, fmt.Errorf("line %d: expected protect field key: value", lineNo)
			}
			switch key {
			case "protect":
				v, err := parseYAMLBool(value)
				if err != nil {
					return cfg, fmt.Errorf("line %d: %w", lineNo, err)
				}
				cfg.Access.Protect = v
			case "user":
				v, err := parseYAMLString(value)
				if err != nil {
					return cfg, fmt.Errorf("line %d: %w", lineNo, err)
				}
				cfg.Access.User = v
			case "password":
				v, err := parseYAMLString(value)
				if err != nil {
					return cfg, fmt.Errorf("line %d: %w", lineNo, err)
				}
				cfg.Access.Password = v
			case "password_env":
				v, err := parseYAMLString(value)
				if err != nil {
					return cfg, fmt.Errorf("line %d: %w", lineNo, err)
				}
				cfg.Access.PasswordEnv = v
			default:
				return cfg, fmt.Errorf("line %d: unknown protect field %q", lineNo, key)
			}
		case sectionTunnels:
			if indent == 2 && strings.HasPrefix(trimmed, "-") {
				cfg.Tunnels = append(cfg.Tunnels, upTunnelConfig{})
				currentTunnel = len(cfg.Tunnels) - 1
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
				if rest == "" {
					continue
				}
				key, value, hasValue, ok := splitYAMLKeyValue(rest)
				if !ok || !hasValue {
					return cfg, fmt.Errorf("line %d: expected list item field after '-'", lineNo)
				}
				if err := setUpTunnelField(&cfg.Tunnels[currentTunnel], key, value); err != nil {
					return cfg, fmt.Errorf("line %d: %w", lineNo, err)
				}
				continue
			}
			if indent != 4 || currentTunnel < 0 {
				return cfg, fmt.Errorf("line %d: tunnel fields must be nested under a '-' item", lineNo)
			}
			key, value, hasValue, ok := splitYAMLKeyValue(trimmed)
			if !ok || !hasValue {
				return cfg, fmt.Errorf("line %d: expected tunnel field key: value", lineNo)
			}
			if err := setUpTunnelField(&cfg.Tunnels[currentTunnel], key, value); err != nil {
				return cfg, fmt.Errorf("line %d: %w", lineNo, err)
			}
		default:
			return cfg, fmt.Errorf("line %d: unexpected indentation", lineNo)
		}
	}

	return cfg, nil
}

func setUpTunnelField(t *upTunnelConfig, key, rawValue string) error {
	if t == nil {
		return errors.New("missing tunnel item")
	}
	switch key {
	case "name":
		v, err := parseYAMLString(rawValue)
		if err != nil {
			return err
		}
		t.Name = v
	case "subdomain":
		v, err := parseYAMLString(rawValue)
		if err != nil {
			return err
		}
		t.Subdomain = v
	case "port":
		n, err := strconv.Atoi(strings.TrimSpace(rawValue))
		if err != nil {
			return errors.New("invalid integer for port")
		}
		t.Port = n
	case "path_prefix":
		v, err := parseYAMLString(rawValue)
		if err != nil {
			return err
		}
		t.PathPrefix = v
	case "strip_prefix":
		v, err := parseYAMLBool(rawValue)
		if err != nil {
			return err
		}
		t.StripPrefix = v
	default:
		return fmt.Errorf("unknown tunnel field %q", key)
	}
	return nil
}

func splitYAMLKeyValue(line string) (key, value string, hasValue bool, ok bool) {
	idx := strings.IndexRune(line, ':')
	if idx < 0 {
		return "", "", false, false
	}
	key = strings.TrimSpace(line[:idx])
	if key == "" {
		return "", "", false, false
	}
	value = strings.TrimSpace(line[idx+1:])
	return key, value, true, true
}

func parseYAMLString(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.HasPrefix(raw, "'") {
		if !strings.HasSuffix(raw, "'") || len(raw) < 2 {
			return "", errors.New("unterminated single-quoted string")
		}
		return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'"), nil
	}
	if strings.HasPrefix(raw, "\"") {
		v, err := strconv.Unquote(raw)
		if err != nil {
			return "", errors.New("invalid double-quoted string")
		}
		return v, nil
	}
	return raw, nil
}

func parseYAMLBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("invalid boolean (expected true or false)")
	}
}

func countLeadingSpaces(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

func stripYAMLComment(s string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				// YAML single-quoted escape is doubled single quote.
				if inSingle && i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				escaped := i > 0 && s[i-1] == '\\'
				if !escaped {
					inDouble = !inDouble
				}
			}
		case '#':
			if !inSingle && !inDouble {
				if i == 0 || s[i-1] == ' ' {
					return strings.TrimRight(s[:i], " ")
				}
			}
		}
	}
	return s
}
