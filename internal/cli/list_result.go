package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/termui"
)

func writeExposureList(out io.Writer, exposures []domain.Exposure, baseDomain string, color bool, columns int) error {
	style := termui.Styler{Color: color}
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s\n", style.Style(termui.Bold, "Your exposures"))
	if len(exposures) == 0 {
		fmt.Fprintf(&b, "\n  %s\n", style.Style(termui.Dim, "No tunnels or published sites found."))
		fmt.Fprintf(&b, "  Start one with %s or %s.\n\n", style.Style(termui.Cyan, "expose http 3000"), style.Style(termui.Cyan, "expose pub ./dist"))
		_, err := io.WriteString(out, b.String())
		return err
	}

	type row struct {
		cells      [5]string
		statusCode string
	}
	headings := [5]string{"NAME", "TYPE", "STATUS", "SEEN", "EXPIRES"}
	widths := [5]int{}
	for i, heading := range headings {
		widths[i] = len(heading)
	}
	rows := make([]row, 0, len(exposures))
	tunnels, sites, online := 0, 0, 0
	now := time.Now()
	for _, e := range exposures {
		kind := e.Type
		switch e.Type {
		case domain.ExposureTypeTunnel:
			tunnels++
			kind = "named"
			if e.Temporary {
				kind = "temp"
			}
		case domain.ExposureTypeSite:
			sites++
			kind = "site"
		}
		marker, statusCode := "○", termui.Dim
		status := e.Status
		switch e.Status {
		case "connected", "active":
			online++
			marker, statusCode = "●", termui.Green
			status = "online"
		case "disconnected":
			status = "offline"
		case "expired":
			marker, statusCode = "×", termui.Red
		}
		expires := "-"
		if e.ExpiresAt != nil {
			expires = e.ExpiresAt.Local().Format("02 Jan 15:04")
		} else if e.Type == domain.ExposureTypeSite {
			expires = "Never"
		}
		host := e.Hostname
		if host == "" {
			host = strings.TrimPrefix(e.URL, "https://")
		}
		name := strings.TrimSuffix(netutil.NormalizeHost(host), "."+netutil.NormalizeHost(baseDomain))
		r := row{cells: [5]string{name, kind, marker + " " + status, exposureLastSeen(e.LastActiveAt, now), expires}, statusCode: statusCode}
		for i := range r.cells {
			r.cells[i] = config.SanitizeTerminalString(r.cells[i])
			widths[i] = max(widths[i], termui.VisibleRuneCount(r.cells[i]))
		}
		rows = append(rows, r)
	}
	summary := fmt.Sprintf("%d %s · %d %s · %d online", tunnels, termui.Pluralize(tunnels, "tunnel"), sites, termui.Pluralize(sites, "site"), online)
	fmt.Fprintf(&b, "  %s\n\n", style.Style(termui.Dim, summary))

	// Cap long names even on wide terminals, then shrink further if needed.
	widths[0] = min(widths[0], 28)
	visibleColumns := len(headings)
	if columns > 0 && columns < 72 {
		visibleColumns-- // Keep name, type, status, and last activity on narrow terminals.
	}
	metadataWidth := (visibleColumns - 1) * 2
	for i := 1; i < visibleColumns; i++ {
		metadataWidth += widths[i]
	}
	if columns > 0 {
		widths[0] = min(widths[0], max(columns-metadataWidth-2, 1))
	}
	tableWidth := widths[0] + metadataWidth
	writeRow := func(cells [5]string, codes [5]string) {
		b.WriteString("  ")
		for i := 0; i < visibleColumns; i++ {
			cell := termui.TruncateRight(cells[i], widths[i])
			b.WriteString(style.Style(codes[i], cell))
			if i < visibleColumns-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-termui.VisibleRuneCount(cell)+2))
			}
		}
		b.WriteByte('\n')
	}
	writeRow(headings, [5]string{termui.Dim, termui.Dim, termui.Dim, termui.Dim, termui.Dim})
	fmt.Fprintf(&b, "  %s\n", style.Style(termui.Dim, strings.Repeat("─", tableWidth)))
	for _, r := range rows {
		writeRow(r.cells, [5]string{termui.Cyan, termui.Dim, r.statusCode, termui.Dim, termui.Dim})
	}
	b.WriteByte('\n')
	_, err := io.WriteString(out, b.String())
	return err
}

func exposureLastSeen(at, now time.Time) string {
	if at.IsZero() {
		return "-"
	}
	age := now.Sub(at)
	switch {
	case age < time.Minute:
		return "now"
	case age < time.Hour:
		return fmt.Sprintf("%dm ago", int(age/time.Minute))
	case age < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(age/time.Hour))
	default:
		return fmt.Sprintf("%dd ago", int(age/(24*time.Hour)))
	}
}
