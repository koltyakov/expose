package client

import (
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const displayMinValueWidth = 16

func (d *Display) fieldValueWidth() int {
	width := displayContentWidth - displayFieldWidth
	if cols := d.terminalColumns(); cols > 0 {
		width = cols - displayFieldWidth
	}
	if width < displayMinValueWidth {
		return displayMinValueWidth
	}
	return width
}

func (d *Display) terminalColumns() int {
	if d != nil && d.terminalColumnsFn != nil {
		return d.terminalColumnsFn()
	}
	return terminalColumnsForWriter(d.out)
}

func terminalColumnsForWriter(w io.Writer) int {
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

func visibleRuneCount(s string) int {
	return utf8.RuneCountInString(s)
}

func wrapPlainText(s string, width int) []string {
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

func wrapTextWithLeadingPrefix(text, prefix string, width int) []string {
	if width < 1 {
		width = 1
	}
	if visibleRuneCount(prefix)+visibleRuneCount(text) <= width {
		return []string{prefix + text}
	}
	runes := []rune(text)
	firstWidth := width - visibleRuneCount(prefix)
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

func wrapTextWithPrefixAndSuffix(text, prefix, suffix string, width int) []string {
	if width < 1 {
		width = 1
	}
	if visibleRuneCount(prefix)+visibleRuneCount(text)+visibleRuneCount(suffix) <= width {
		return []string{prefix + text + suffix}
	}

	runes := []rune(text)
	firstWidth := width - visibleRuneCount(prefix)
	if firstWidth < 1 {
		firstWidth = 1
	}
	firstLen := firstWidth
	if firstLen > len(runes) {
		firstLen = len(runes)
	}
	lines := []string{prefix + string(runes[:firstLen])}
	runes = runes[firstLen:]

	lastWidth := width - visibleRuneCount(suffix)
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

func (d *Display) forwardingDisplayLines() []string {
	publicURL := strings.TrimSpace(d.publicURL)
	if publicURL == "" {
		return []string{d.styled(ansiDim, "--")}
	}

	width := d.fieldValueWidth()
	localAddr := strings.TrimSpace(d.localAddr)
	localHealthy := localAddr != "" && d.localTargetHealthy(localAddr)
	localTailWidth := visibleRuneCount("→ ") + visibleRuneCount(localAddr)
	if localAddr != "" {
		localTailWidth += visibleRuneCount(" ●")
	} else {
		localTailWidth += visibleRuneCount("--")
	}
	externalWidth := visibleRuneCount(publicURL)
	if d.protected {
		externalWidth += visibleRuneCount(displayLockIcon + " ")
	}
	if externalWidth+1+localTailWidth <= width {
		return []string{d.renderForwardingExternalLine(publicURL, d.protected) + " " + d.renderForwardingLocalLine(localAddr, localHealthy, true)}
	}

	lines := d.forwardingExternalLines(publicURL, width, d.protected)
	return append(lines, d.forwardingLocalLines(localAddr, localHealthy, width)...)
}

func (d *Display) forwardingExternalLines(publicURL string, width int, protected bool) []string {
	if !protected {
		chunks := wrapPlainText(publicURL, width)
		lines := make([]string, 0, len(chunks))
		for _, chunk := range chunks {
			lines = append(lines, d.styled(ansiCyan, chunk))
		}
		return lines
	}

	rawLines := wrapTextWithLeadingPrefix(publicURL, displayLockIcon+" ", width)
	lines := make([]string, 0, len(rawLines))
	for i, line := range rawLines {
		if i == 0 && strings.HasPrefix(line, displayLockIcon+" ") {
			lines = append(lines, d.renderForwardingExternalLine(strings.TrimPrefix(line, displayLockIcon+" "), true))
			continue
		}
		lines = append(lines, d.styled(ansiCyan, line))
	}
	return lines
}

func (d *Display) forwardingLocalLines(localAddr string, healthy bool, width int) []string {
	if strings.TrimSpace(localAddr) == "" {
		return []string{d.styled(ansiDim, "→") + " " + d.styled(ansiDim, "--")}
	}
	rawLines := wrapTextWithPrefixAndSuffix(localAddr, "→ ", " ●", width)
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		lines = append(lines, d.renderForwardingLocalWrappedLine(line, healthy))
	}
	return lines
}

func (d *Display) renderForwardingExternalLine(publicURL string, protected bool) string {
	if protected {
		return d.styled(ansiYellow, displayLockIcon) + " " + d.styled(ansiCyan, publicURL)
	}
	return d.styled(ansiCyan, publicURL)
}

func (d *Display) renderForwardingLocalLine(localAddr string, healthy bool, includeDot bool) string {
	if strings.TrimSpace(localAddr) == "" {
		return d.styled(ansiDim, "→") + " " + d.styled(ansiDim, "--")
	}
	line := d.styled(ansiDim, "→") + " " + localAddr
	if includeDot {
		color := ansiRed
		if healthy {
			color = ansiGreen
		}
		line += d.styled(color, " ●")
	}
	return line
}

func (d *Display) renderForwardingLocalWrappedLine(line string, healthy bool) string {
	var b strings.Builder
	if strings.HasPrefix(line, "→ ") {
		b.WriteString(d.styled(ansiDim, "→"))
		b.WriteString(" ")
		line = strings.TrimPrefix(line, "→ ")
	}
	if strings.HasSuffix(line, " ●") {
		body := strings.TrimSuffix(line, " ●")
		b.WriteString(body)
		color := ansiRed
		if healthy {
			color = ansiGreen
		}
		b.WriteString(d.styled(color, " ●"))
		return b.String()
	}
	b.WriteString(line)
	return b.String()
}
