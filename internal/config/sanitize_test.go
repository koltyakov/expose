package config

import (
	"strings"
	"testing"
)

func TestSanitizeTerminalStringReplacesControlRunes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "clean path", in: "/api/health?q=1", want: "/api/health?q=1"},
		{name: "empty", in: "", want: ""},
		{name: "escape sequence", in: "/\x1b[2Jlogin", want: "/�[2Jlogin"},
		{name: "percent decoded esc", in: "/%1b", want: "/%1b"},
		{name: "newline", in: "GET /\nHost: evil", want: "GET /�Host: evil"},
		{name: "carriage return", in: "/a\r\rb", want: "/a��b"},
		{name: "tab", in: "/a\tb", want: "/a�b"},
		{name: "null byte", in: "/a\x00b", want: "/a�b"},
		{name: "delete", in: "/a\x7fb", want: "/a�b"},
		{name: "c1 csi", in: "/a\x9bb", want: "/a�b"},
		{name: "c1 nel", in: "/a\x85b", want: "/a�b"},
		{name: "unicode kept", in: "/café/日本語", want: "/café/日本語"},
	}
	for _, tt := range cases {
		if got := SanitizeTerminalString(tt.in); got != tt.want {
			t.Fatalf("%s: SanitizeTerminalString(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestRedactQueryValues(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "token=abc123", want: "token=REDACTED"},
		{in: "a=1&b=2", want: "a=REDACTED&b=REDACTED"},
		{in: "flag&token=abc", want: "flag&token=REDACTED"},
		{in: "sig=", want: "sig=REDACTED"},
		{in: "  ", want: ""},
	}
	for _, tt := range cases {
		if got := RedactQueryValues(tt.in); got != tt.want {
			t.Fatalf("RedactQueryValues(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if got := RedactQueryValues("sig=a=b=c"); !strings.HasPrefix(got, "sig=REDACTED") {
		t.Fatalf("expected value with '=' fully redacted, got %q", got)
	}
}
