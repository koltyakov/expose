package termui

import (
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

func TerminalColumnsForWriter(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if cols, _, err := term.GetSize(int(f.Fd())); err == nil && cols > 0 {
			return cols
		}
	}
	if raw := strings.TrimSpace(os.Getenv("COLUMNS")); raw != "" {
		if cols, err := strconv.Atoi(raw); err == nil && cols > 0 {
			return cols
		}
	}
	return 0
}

func VisibleRuneCount(s string) int {
	return utf8.RuneCountInString(s)
}

func WrapPlainText(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return []string{""}
	}
	lines := make([]string, 0, (len(runes)+width-1)/width)
	for len(runes) > 0 {
		n := width
		if n > len(runes) {
			n = len(runes)
		}
		lines = append(lines, string(runes[:n]))
		runes = runes[n:]
	}
	return lines
}

func WrapTextWithLeadingPrefix(text, prefix string, width int) []string {
	if width < 1 {
		width = 1
	}
	if VisibleRuneCount(prefix)+VisibleRuneCount(text) <= width {
		return []string{prefix + text}
	}
	runes := []rune(text)
	firstWidth := width - VisibleRuneCount(prefix)
	if firstWidth < 1 {
		firstWidth = 1
	}
	firstLen := firstWidth
	if firstLen > len(runes) {
		firstLen = len(runes)
	}
	lines := []string{prefix + string(runes[:firstLen])}
	runes = runes[firstLen:]
	for len(runes) > 0 {
		n := width
		if n > len(runes) {
			n = len(runes)
		}
		lines = append(lines, string(runes[:n]))
		runes = runes[n:]
	}
	return lines
}

func WrapTextWithPrefixAndSuffix(text, prefix, suffix string, width int) []string {
	if width < 1 {
		width = 1
	}
	if VisibleRuneCount(prefix)+VisibleRuneCount(text)+VisibleRuneCount(suffix) <= width {
		return []string{prefix + text + suffix}
	}

	runes := []rune(text)
	firstWidth := width - VisibleRuneCount(prefix)
	if firstWidth < 1 {
		firstWidth = 1
	}
	firstLen := firstWidth
	if firstLen > len(runes) {
		firstLen = len(runes)
	}
	lines := []string{prefix + string(runes[:firstLen])}
	runes = runes[firstLen:]

	lastWidth := width - VisibleRuneCount(suffix)
	if lastWidth < 1 {
		lastWidth = 1
	}
	for len(runes) > lastWidth {
		n := len(runes) - lastWidth
		if n > width {
			n = width
		}
		if n < 1 {
			n = 1
		}
		lines = append(lines, string(runes[:n]))
		runes = runes[n:]
	}
	lines = append(lines, string(runes)+suffix)
	return lines
}

func TruncateRight(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if VisibleRuneCount(s) <= width {
		return s
	}
	runes := []rune(s)
	if width <= 3 {
		return string(runes[:width])
	}
	if len(runes) <= width {
		return s
	}
	return string(runes[:width-3]) + "..."
}

func WriteFieldLines(b *strings.Builder, fieldWidth int, label string, values []string) {
	if len(values) == 0 {
		values = []string{""}
	}
	for i, value := range values {
		currentLabel := ""
		if i == 0 {
			currentLabel = label
		}
		pad := fieldWidth - len(currentLabel)
		if pad < 1 {
			pad = 1
		}
		b.WriteString(currentLabel)
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(value)
		b.WriteByte('\n')
	}
}
