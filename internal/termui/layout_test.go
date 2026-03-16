package termui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalColumnsForWriterUsesEnvFallback(t *testing.T) {
	t.Setenv("COLUMNS", "120")

	if got := TerminalColumnsForWriter(&bytes.Buffer{}); got != 120 {
		t.Fatalf("TerminalColumnsForWriter() = %d, want %d", got, 120)
	}
}

func TestTerminalColumnsForWriterRejectsInvalidEnv(t *testing.T) {
	t.Setenv("COLUMNS", "invalid")

	if got := TerminalColumnsForWriter(&bytes.Buffer{}); got != 0 {
		t.Fatalf("TerminalColumnsForWriter() = %d, want %d", got, 0)
	}
}

func TestVisibleRuneCount(t *testing.T) {
	t.Parallel()

	if got := VisibleRuneCount("Go語"); got != 3 {
		t.Fatalf("VisibleRuneCount() = %d, want %d", got, 3)
	}
}

func TestWrapPlainText(t *testing.T) {
	t.Parallel()

	got := WrapPlainText("abcdef", 2)
	want := []string{"ab", "cd", "ef"}
	if !equalStrings(got, want) {
		t.Fatalf("WrapPlainText() = %#v, want %#v", got, want)
	}
}

func TestWrapPlainTextHandlesEmptyAndSmallWidth(t *testing.T) {
	t.Parallel()

	if got := WrapPlainText("", 0); !equalStrings(got, []string{""}) {
		t.Fatalf("WrapPlainText(empty) = %#v, want %#v", got, []string{""})
	}
	if got := WrapPlainText("ab", 0); !equalStrings(got, []string{"a", "b"}) {
		t.Fatalf("WrapPlainText(width<1) = %#v, want %#v", got, []string{"a", "b"})
	}
}

func TestWrapTextWithLeadingPrefix(t *testing.T) {
	t.Parallel()

	got := WrapTextWithLeadingPrefix("abcdef", "> ", 4)
	want := []string{"> ab", "cdef"}
	if !equalStrings(got, want) {
		t.Fatalf("WrapTextWithLeadingPrefix() = %#v, want %#v", got, want)
	}
}

func TestWrapTextWithPrefixAndSuffix(t *testing.T) {
	t.Parallel()

	got := WrapTextWithPrefixAndSuffix("abcdef", "> ", " <", 4)
	want := []string{"> ab", "cd", "ef <"}
	if !equalStrings(got, want) {
		t.Fatalf("WrapTextWithPrefixAndSuffix() = %#v, want %#v", got, want)
	}
}

func TestTruncateRight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		width int
		want  string
	}{
		{input: "abcdef", width: 0, want: ""},
		{input: "abcdef", width: 3, want: "abc"},
		{input: "abcdef", width: 5, want: "ab..."},
		{input: "abc", width: 5, want: "abc"},
	}

	for _, tt := range tests {
		if got := TruncateRight(tt.input, tt.width); got != tt.want {
			t.Fatalf("TruncateRight(%q, %d) = %q, want %q", tt.input, tt.width, got, tt.want)
		}
	}
}

func TestWriteFieldLines(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	WriteFieldLines(&b, 6, "Name", []string{"Alice", "Bob"})

	want := "Name  Alice\n      Bob\n"
	if got := b.String(); got != want {
		t.Fatalf("WriteFieldLines() = %q, want %q", got, want)
	}
}

func TestWriteFieldLinesHandlesEmptyValues(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	WriteFieldLines(&b, 4, "ID", nil)

	want := "ID  \n"
	if got := b.String(); got != want {
		t.Fatalf("WriteFieldLines() = %q, want %q", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
