package cli

import (
	"strings"

	"github.com/koltyakov/expose/internal/termui"
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
	return termui.TerminalColumnsForWriter(d.out)
}

func (d *upDashboard) forwardingValueLinesLocked(external, local string, healthy bool) []string {
	width := d.fieldValueWidth()
	localTailWidth := termui.VisibleRuneCount("→ ") + termui.VisibleRuneCount(local) + termui.VisibleRuneCount(" ●")
	if termui.VisibleRuneCount(external)+1+localTailWidth <= width {
		return []string{d.styled(upANSICyan, external) + " " + d.renderForwardingLocalLine(local, healthy, true)}
	}

	lines := make([]string, 0, 2)
	for _, chunk := range termui.WrapPlainText(external, width) {
		lines = append(lines, d.styled(upANSICyan, chunk))
	}
	for _, line := range termui.WrapTextWithPrefixAndSuffix(local, "→ ", " ●", width) {
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
	if before, ok := strings.CutSuffix(line, " ●"); ok {
		body := before
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
