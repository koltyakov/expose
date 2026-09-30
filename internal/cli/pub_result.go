package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/termui"
)

func writePublishedSiteResult(out io.Writer, site domain.PublishedSite, color bool) error {
	style := termui.Styler{Color: color}
	hostname := config.SanitizeTerminalString(site.Hostname)
	subdomain, _, _ := strings.Cut(hostname, ".")
	expiry := "No expiry"
	if site.ExpiresAt != nil {
		expiry = site.ExpiresAt.Local().Format("2 Jan 2006, 15:04:05 MST")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s %s\n\n", style.Style(termui.Bold+termui.Green, "Published"), style.Style(termui.Bold, subdomain))
	fmt.Fprintf(&b, "  %s%s\n", style.Style(termui.Dim, fmt.Sprintf("%-12s", "Public URL")), style.Style(termui.Bold+termui.Cyan, "https://"+hostname))
	fmt.Fprintf(&b, "  %s%s\n\n", style.Style(termui.Dim, fmt.Sprintf("%-12s", "Expires")), expiry)
	_, err := io.WriteString(out, b.String())
	return err
}
