package cli

import (
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const upDisplayMinValueWidth = 16

func (d *upDashboard) fieldValueWidth() int {
	width := upDisplayContentWidth - upDisplayFieldWidth
	if cols := d.terminalColumns(); cols > 0 {
		width = cols - upDisplayFieldWidth
	}
	if width < upDisplayMinValueWidth {
		return upDisplayMinValueWidth
	}
	return width
}

func (d *upDashboard) terminalColumns() int {
	if d != nil && d.terminalColumnsFn != nil {
		return d.terminalColumnsFn()
	}
	return upTerminalColumnsForWriter(d.out)
}

func upTerminalColumnsForWriter(w io.Writer) int {
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

func upVisibleRuneCount(s string) int {
	return utf8.RuneCountInString(s)
}

func upWrapPlainText(s string, width int) []string {
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

func upWrapTextWithPrefixAndSuffix(text, prefix, suffix string, width int) []string {
	if width < 1 {
		width = 1
	}
	if upVisibleRuneCount(prefix)+upVisibleRuneCount(text)+upVisibleRuneCount(suffix) <= width {
		return []string{prefix + text + suffix}
	}

	runes := []rune(text)
	firstWidth := width - upVisibleRuneCount(prefix)
	if firstWidth < 1 {
		firstWidth = 1
	}
	firstLen := firstWidth
	if firstLen > len(runes) {
		firstLen = len(runes)
	}
	lines := []string{prefix + string(runes[:firstLen])}
	runes = runes[firstLen:]

	lastWidth := width - upVisibleRuneCount(suffix)
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

func (d *upDashboard) forwardingValueLinesLocked(external, local string, healthy bool) []string {
	width := d.fieldValueWidth()
	localTailWidth := upVisibleRuneCount("→ ") + upVisibleRuneCount(local) + upVisibleRuneCount(" ●")
	if upVisibleRuneCount(external)+1+localTailWidth <= width {
		return []string{d.styled(upANSICyan, external) + " " + d.renderForwardingLocalLine(local, healthy, true)}
	}

	lines := make([]string, 0, 2)
	for _, chunk := range upWrapPlainText(external, width) {
		lines = append(lines, d.styled(upANSICyan, chunk))
	}
	for _, line := range upWrapTextWithPrefixAndSuffix(local, "→ ", " ●", width) {
		lines = append(lines, d.renderForwardingLocalWrappedLine(line, healthy))
	}
	return lines
}

func (d *upDashboard) renderForwardingLocalLine(local string, healthy bool, includeDot bool) string {
	line := d.styled(upANSIDim, "→") + " " + local
	if includeDot {
		color := upANSIRed
		if healthy {
			color = upANSIGreen
		}
		line += d.styled(color, " ●")
	}
	return line
}

func (d *upDashboard) renderForwardingLocalWrappedLine(line string, healthy bool) string {
	var b strings.Builder
	if strings.HasPrefix(line, "→ ") {
		b.WriteString(d.styled(upANSIDim, "→"))
		b.WriteString(" ")
		line = strings.TrimPrefix(line, "→ ")
	}
	if strings.HasSuffix(line, " ●") {
		body := strings.TrimSuffix(line, " ●")
		b.WriteString(body)
		color := upANSIRed
		if healthy {
			color = upANSIGreen
		}
		b.WriteString(d.styled(color, " ●"))
		return b.String()
	}
	b.WriteString(line)
	return b.String()
}
