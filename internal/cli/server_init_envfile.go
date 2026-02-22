package cli

import (
	"errors"
	"os"
	"strings"
)

func loadEnvFileValues(path string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	for _, line := range lines {
		key, value, ok := parseEnvAssignment(line)
		if !ok {
			continue
		}
		out[key] = value
	}
	return out
}

func buildInitEnvEntries(a serverInitAnswers) []envEntry {
	entries := []envEntry{
		{Key: "EXPOSE_DOMAIN", Value: a.BaseDomain},
		{Key: "EXPOSE_LISTEN_HTTPS", Value: a.ListenHTTPS},
		{Key: "EXPOSE_TLS_MODE", Value: a.TLSMode},
	}
	if a.TLSMode == "wildcard" {
		entries = appendInitDBAndCertEntries(entries, a)
		entries = append(entries,
			envEntry{Key: "EXPOSE_TLS_CERT_FILE", Value: a.TLSCertFile},
			envEntry{Key: "EXPOSE_TLS_KEY_FILE", Value: a.TLSKeyFile},
		)
	} else {
		entries = append(entries,
			envEntry{Key: "EXPOSE_LISTEN_HTTP_CHALLENGE", Value: a.ListenHTTP},
		)
		entries = appendInitDBAndCertEntries(entries, a)
	}
	entries = append(entries,
		envEntry{Key: "EXPOSE_LOG_LEVEL", Value: a.LogLevel},
		envEntry{Key: "EXPOSE_API_KEY_PEPPER", Value: a.APIKeyPepper},
	)
	if strings.TrimSpace(a.GeneratedKey) != "" {
		entries = append(entries, envEntry{Key: "EXPOSE_API_KEY", Value: a.GeneratedKey})
	}
	return entries
}

func appendInitDBAndCertEntries(entries []envEntry, a serverInitAnswers) []envEntry {
	return append(entries,
		envEntry{Key: "EXPOSE_DB_PATH", Value: a.DBPath},
		envEntry{Key: "EXPOSE_CERT_CACHE_DIR", Value: a.CertCacheDir},
	)
}

func upsertEnvFile(path string, entries []envEntry) error {
	byKey := make(map[string]string, len(entries))
	order := make([]string, 0, len(entries))
	for _, entry := range entries {
		key := strings.TrimSpace(entry.Key)
		if key == "" {
			continue
		}
		if _, seen := byKey[key]; !seen {
			order = append(order, key)
		}
		byKey[key] = sanitizeEnvValue(entry.Value)
	}

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	var lines []string
	if len(raw) > 0 {
		normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
		normalized = strings.TrimRight(normalized, "\n")
		if normalized != "" {
			lines = strings.Split(normalized, "\n")
		}
	}

	updated := make(map[string]bool, len(byKey))
	for i, line := range lines {
		key, _, ok := parseEnvAssignment(line)
		if !ok {
			continue
		}
		value, wanted := byKey[key]
		if !wanted {
			continue
		}
		lines[i] = formatEnvEntry(key, value)
		updated[key] = true
	}

	pending := make([]string, 0, len(order))
	for _, key := range order {
		if !updated[key] {
			pending = append(pending, key)
		}
	}
	if len(pending) > 0 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "# Added by expose server init")
		for _, key := range pending {
			lines = append(lines, formatEnvEntry(key, byKey[key]))
		}
	}

	if len(lines) == 0 {
		lines = append(lines, "# Added by expose server init")
		for _, key := range order {
			lines = append(lines, formatEnvEntry(key, byKey[key]))
		}
	}

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}

func parseEnvAssignment(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	if strings.HasPrefix(trimmed, "export ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
	}
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
			(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, true
}

func formatEnvEntry(key, value string) string {
	return key + "=" + value
}

func sanitizeEnvValue(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return strings.TrimSpace(v)
}
