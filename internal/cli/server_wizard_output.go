package cli

import (
	"fmt"
	"io"
	"strings"
)

func printWizardNextSteps(out io.Writer, a serverWizardAnswers) {
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Next steps")
	_, _ = fmt.Fprintln(out, "  1) Start the server")
	_, _ = fmt.Fprintln(out, "     expose server")

	if strings.TrimSpace(a.GeneratedKey) != "" {
		_, _ = fmt.Fprintln(out, "  2) Login client (API key was generated and saved to .env)")
		_, _ = fmt.Fprintf(out, "     expose login --server %s --api-key %s\n", a.BaseDomain, a.GeneratedKey)
	} else {
		_, _ = fmt.Fprintln(out, "  2) Create API key, then login client")
		_, _ = fmt.Fprintln(out, "     expose apikey create --name default")
		_, _ = fmt.Fprintf(out, "     expose login --server %s --api-key <PASTE_KEY>\n", a.BaseDomain)
	}
	_, _ = fmt.Fprintln(out, "  3) Expose a local app")
	_, _ = fmt.Fprintln(out, "     expose http 3000")
}
