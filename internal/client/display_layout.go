package client

import (
	"strings"

	"github.com/koltyakov/expose/internal/termui"
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
	return termui.TerminalColumnsForWriter(d.out)
}

func (d *Display) forwardingDisplayLines() []string {
	publicURL := strings.TrimSpace(d.publicURL)
	if publicURL == "" {
		return []string{d.styled(ansiDim, "--")}
	}

	width := d.fieldValueWidth()
	localAddr := strings.TrimSpace(d.localAddr)
	localHealthy := localAddr != "" && d.localTargetHealthy(localAddr)
	localTailWidth := termui.VisibleRuneCount("→ ") + termui.VisibleRuneCount(localAddr)
	if localAddr != "" {
		localTailWidth += termui.VisibleRuneCount(" ●")
	} else {
		localTailWidth += termui.VisibleRuneCount("--")
	}
	externalWidth := termui.VisibleRuneCount(publicURL)
	if d.protected {
		externalWidth += termui.VisibleRuneCount(displayLockIcon + " ")
	}
	if externalWidth+1+localTailWidth <= width {
		return []string{d.renderForwardingExternalLine(publicURL, d.protected) + " " + d.renderForwardingLocalLine(localAddr, localHealthy, true)}
	}

	lines := d.forwardingExternalLines(publicURL, width, d.protected)
	return append(lines, d.forwardingLocalLines(localAddr, localHealthy, width)...)
}

func (d *Display) forwardingExternalLines(publicURL string, width int, protected bool) []string {
	if !protected {
		chunks := termui.WrapPlainText(publicURL, width)
		lines := make([]string, 0, len(chunks))
		for _, chunk := range chunks {
			lines = append(lines, d.styled(ansiCyan, chunk))
		}
		return lines
	}

	rawLines := termui.WrapTextWithLeadingPrefix(publicURL, displayLockIcon+" ", width)
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
	rawLines := termui.WrapTextWithPrefixAndSuffix(localAddr, "→ ", " ●", width)
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
	if before, ok := strings.CutSuffix(line, " ●"); ok {
		body := before
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
