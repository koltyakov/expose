package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/termui"
)

func writeExposureList(out io.Writer, exposures []domain.Exposure, color bool, columns int) error {
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
		cells      [4]string
		statusCode string
	}
	headings := [4]string{"PUBLIC URL", "TYPE", "STATUS", "EXPIRES"}
	widths := [4]int{}
	for i, heading := range headings {
		widths[i] = len(heading)
	}
	rows := make([]row, 0, len(exposures))
	tunnels, sites, online := 0, 0, 0
	for _, e := range exposures {
		kind := e.Type
		switch e.Type {
		case domain.ExposureTypeTunnel:
			tunnels++
			kind = "named tunnel"
			if e.Temporary {
				kind = "temporary tunnel"
			}
		case domain.ExposureTypeSite:
			sites++
			kind = "published site"
		}
		marker, statusCode := "○", termui.Dim
		switch e.Status {
		case "connected", "active":
			online++
			marker, statusCode = "●", termui.Green
		case "disconnected":
			statusCode = termui.Yellow
		case "expired":
			marker, statusCode = "×", termui.Red
		}
		expires := "-"
		if e.ExpiresAt != nil {
			expires = e.ExpiresAt.Local().Format("02 Jan 2006 15:04 MST")
		} else if e.Type == domain.ExposureTypeSite {
			expires = "No expiry"
		}
		r := row{cells: [4]string{e.URL, kind, marker + " " + e.Status, expires}, statusCode: statusCode}
		for i := range r.cells {
			r.cells[i] = config.SanitizeTerminalString(r.cells[i])
			widths[i] = max(widths[i], termui.VisibleRuneCount(r.cells[i]))
		}
		rows = append(rows, r)
	}
	summary := fmt.Sprintf("%d %s · %d %s · %d online", tunnels, termui.Pluralize(tunnels, "tunnel"), sites, termui.Pluralize(sites, "site"), online)
	fmt.Fprintf(&b, "  %s\n\n", style.Style(termui.Dim, summary))

	tableWidth := widths[0] + widths[1] + widths[2] + widths[3] + 6
	if columns > 0 && tableWidth+2 > columns {
		// Keep URLs intact so terminals can wrap and recognize them as links.
		for _, r := range rows {
			fmt.Fprintf(&b, "  %s\n", style.Style(termui.Bold+termui.Cyan, r.cells[0]))
			fmt.Fprintf(&b, "  %s  %s  %s\n", style.Style(termui.Dim, r.cells[1]), style.Style(termui.Dim, "·"), style.Style(r.statusCode, r.cells[2]))
			if r.cells[3] != "-" {
				fmt.Fprintf(&b, "  %s %s\n", style.Style(termui.Dim, "Expiry"), style.Style(termui.Dim, r.cells[3]))
			}
			b.WriteByte('\n')
		}
	} else {
		writeRow := func(cells [4]string, codes [4]string) {
			b.WriteString("  ")
			for i, cell := range cells {
				b.WriteString(style.Style(codes[i], cell))
				if i < len(cells)-1 {
					b.WriteString(strings.Repeat(" ", widths[i]-termui.VisibleRuneCount(cell)+2))
				}
			}
			b.WriteByte('\n')
		}
		writeRow(headings, [4]string{termui.Dim, termui.Dim, termui.Dim, termui.Dim})
		fmt.Fprintf(&b, "  %s\n", style.Style(termui.Dim, strings.Repeat("─", tableWidth)))
		for _, r := range rows {
			writeRow(r.cells, [4]string{termui.Bold + termui.Cyan, termui.Dim, r.statusCode, termui.Dim})
		}
		b.WriteByte('\n')
	}
	_, err := io.WriteString(out, b.String())
	return err
}
