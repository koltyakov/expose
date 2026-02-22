package cli

import (
	"errors"
	"strings"

	"github.com/koltyakov/expose/internal/netutil"
)

func validateWizardDomain(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("domain is required")
	}
	if strings.Contains(v, "/") {
		return errors.New("domain must be a host, not a URL path")
	}
	return nil
}

func validateWizardNonEmpty(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("value is required")
	}
	return nil
}

func validateWizardAny(string) error {
	return nil
}

func validateWizardTLSMode(v string) error {
	switch v {
	case "dynamic", "wildcard":
		return nil
	default:
		return errors.New("must be one of: dynamic, wildcard")
	}
}

func validateWizardLogLevel(v string) error {
	switch v {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return errors.New("must be one of: debug, info, warn, error")
	}
}

func normalizeWizardDomain(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		raw = strings.TrimPrefix(raw, "https://")
		raw = strings.TrimPrefix(raw, "http://")
	}
	raw = strings.TrimSuffix(raw, "/")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	return netutil.NormalizeHost(raw)
}

func normalizeWizardTLSMode(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeWizardLogLevel(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
