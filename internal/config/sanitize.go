package config

import (
	"strings"
	"unicode/utf8"
)

// SanitizeTerminalString replaces C0/C1 control characters in
// attacker-controlled strings (request methods, paths, queries) with a
// visible placeholder so they cannot inject terminal escape sequences into
// dashboards or log output. Lone bytes in the control ranges (invalid UTF-8)
// are replaced as well; valid multi-byte runes are preserved.
func SanitizeTerminalString(s string) string {
	if s == "" || (!strings.ContainsFunc(s, isTerminalControlRune) && utf8.ValidString(s)) {
		return s
	}
	changed := false
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if isTerminalControlByte(s[i]) {
				b.WriteRune('�')
				changed = true
			} else {
				b.WriteByte(s[i])
			}
			i++
			continue
		}
		if isTerminalControlRune(r) {
			b.WriteRune('�')
			changed = true
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	if !changed {
		return s
	}
	return b.String()
}

func isTerminalControlRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

func isTerminalControlByte(b byte) bool {
	return b < 0x20 || (b >= 0x7f && b <= 0x9f)
}

// RedactQueryValues keeps query parameter keys but replaces every value so
// secrets such as ?token= or ?sig= do not end up in operator logs.
func RedactQueryValues(rawQuery string) string {
	rawQuery = strings.TrimSpace(rawQuery)
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	for i, part := range parts {
		key, _, hasValue := strings.Cut(part, "=")
		if !hasValue {
			continue
		}
		parts[i] = key + "=REDACTED"
	}
	return strings.Join(parts, "&")
}
