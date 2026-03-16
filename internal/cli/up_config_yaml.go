package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func renderUpYAML(cfg upConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %d\n", cfg.Version)
	if cfg.Server != "" {
		fmt.Fprintf(&b, "server: %s\n", yamlQuoteString(cfg.Server))
	}
	if cfg.APIKey != "" {
		fmt.Fprintf(&b, "api_key: %s\n", yamlQuoteString(cfg.APIKey))
	}
	if cfg.Access.Protect || cfg.Access.User != "" || cfg.Access.Password != "" {
		b.WriteString("protect:\n")
		if cfg.Access.Protect {
			fmt.Fprintf(&b, "  protect: %t\n", cfg.Access.Protect)
		}
		if cfg.Access.User != "" {
			fmt.Fprintf(&b, "  user: %s\n", yamlQuoteString(cfg.Access.User))
		}
		if cfg.Access.Password != "" {
			fmt.Fprintf(&b, "  password: %s\n", yamlQuoteString(cfg.Access.Password))
		}
	}
	b.WriteString("tunnels:\n")
	for _, t := range cfg.Tunnels {
		b.WriteString("  - ")
		fmt.Fprintf(&b, "name: %s\n", yamlQuoteString(t.Name))
		fmt.Fprintf(&b, "    subdomain: %s\n", yamlQuoteString(t.Subdomain))
		if t.Dir != "" {
			fmt.Fprintf(&b, "    dir: %s\n", yamlQuoteString(t.Dir))
			if t.SPA {
				fmt.Fprintf(&b, "    spa: %t\n", t.SPA)
			}
			if t.Folders {
				fmt.Fprintf(&b, "    folders: %t\n", t.Folders)
			}
		} else {
			fmt.Fprintf(&b, "    port: %d\n", t.Port)
		}
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
	case "dir", "static_dir":
		v, err := parseYAMLString(rawValue)
		if err != nil {
			return err
		}
		t.Dir = v
	case "spa":
		v, err := parseYAMLBool(rawValue)
		if err != nil {
			return err
		}
		t.SPA = v
	case "folders":
		v, err := parseYAMLBool(rawValue)
		if err != nil {
			return err
		}
		t.Folders = v
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
