package versionutil

// EnsureVPrefix returns s with a leading "v" if it doesn't already have one.
// Only numbered versions get the prefix; labels such as "dev" stay as they are.
func EnsureVPrefix(s string) string {
	if s != "" && s[0] >= '0' && s[0] <= '9' {
		return "v" + s
	}
	return s
}
