package selfupdate

import "strings"

// IsNewer reports whether latest is a newer semver than current.
// Optional "v" prefixes are accepted. Versioned development builds compare using
// their base version; plain "dev" builds can update to any release version.
// Invalid versions and development update targets are ignored.
func IsNewer(current, latest string) bool {
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	latest = strings.TrimPrefix(strings.TrimSpace(latest), "v")
	if strings.HasSuffix(latest, "-dev") || parseSemver(latest) == nil {
		return false
	}
	if current == "dev" {
		return true
	}
	if parseSemver(current) == nil {
		return false
	}
	return isNewer(current, latest)
}

// isNewer returns true when latest > current using simple semver comparison.
// Both strings should already have the "v" prefix stripped.
func isNewer(current, latest string) bool {
	cp := parseSemver(current)
	lp := parseSemver(latest)
	if cp == nil || lp == nil {
		// Fall back to string comparison if parsing fails.
		return latest > current
	}
	if lp[0] != cp[0] {
		return lp[0] > cp[0]
	}
	if lp[1] != cp[1] {
		return lp[1] > cp[1]
	}
	return lp[2] > cp[2]
}

func parseSemver(v string) []int {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	nums := make([]int, 3)
	for i, p := range parts {
		// Strip pre-release suffix (e.g. "0-rc1") for comparison.
		p = strings.SplitN(p, "-", 2)[0]
		p = strings.SplitN(p, "+", 2)[0]
		if p == "" {
			return nil
		}
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return nil
			}
			n = n*10 + int(ch-'0')
		}
		nums[i] = n
	}
	return nums
}
