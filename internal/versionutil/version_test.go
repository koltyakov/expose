package versionutil

import "testing"

func TestEnsureVPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: "v1.2.3", want: "v1.2.3"},
		{input: "1.2.3", want: "v1.2.3"},
	}

	for _, tt := range tests {
		if got := EnsureVPrefix(tt.input); got != tt.want {
			t.Fatalf("EnsureVPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
