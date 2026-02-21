package versionutil

import "strings"

// EnsureVPrefix returns s with a leading "v" if it doesn't already have one.
func EnsureVPrefix(s string) string {
	if s != "" && !strings.HasPrefix(s, "v") {
		return "v" + s
	}
	return s
}
