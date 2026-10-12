package config

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ServerBypass proxies a reserved subdomain directly to a loopback HTTP port.
// Security opt-outs are false by default and can only be configured by the server.
type ServerBypass struct {
	Subdomain        string `json:"subdomain"`
	Port             int    `json:"port"`
	DisableWAF       bool   `json:"disable_waf,omitempty"`
	DisableRateLimit bool   `json:"disable_rate_limit,omitempty"`
}

func parseServerBypasses(raw, baseDomain string) ([]ServerBypass, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var routes []ServerBypass
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&routes); err != nil {
		return nil, fmt.Errorf("invalid server bypasses: %w", err)
	}
	if routes == nil {
		return nil, fmt.Errorf("server bypasses must be a JSON array")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("server bypasses must contain a single JSON array")
	}
	seen := make(map[string]bool, len(routes))
	for i := range routes {
		route := &routes[i]
		route.Subdomain = NormalizeTunnelSubdomain(route.Subdomain)
		if route.Subdomain == "" {
			return nil, fmt.Errorf("server bypass subdomain is required")
		}
		if err := ValidateTunnelSubdomain(route.Subdomain); err != nil {
			return nil, fmt.Errorf("invalid server bypass subdomain: %w", err)
		}
		if err := validateHostnameSyntax(route.Subdomain + "." + baseDomain); err != nil {
			return nil, fmt.Errorf("invalid server bypass hostname: %w", err)
		}
		if route.Port < 1 || route.Port > 65535 {
			return nil, fmt.Errorf("server bypass %q port must be between 1 and 65535", route.Subdomain)
		}
		if seen[route.Subdomain] {
			return nil, fmt.Errorf("duplicate server bypass subdomain %q", route.Subdomain)
		}
		seen[route.Subdomain] = true
	}
	return routes, nil
}
