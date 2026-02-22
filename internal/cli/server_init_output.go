package cli

import (
	"fmt"
	"io"
	"strings"
)

func printInitNextSteps(out io.Writer, a serverInitAnswers) {
	ui := newWizardTUI()
	_, _ = fmt.Fprintln(out)
	ui.printSection(out, "Next Steps")
	_, _ = fmt.Fprintln(out, "  1) Start the server")
	_, _ = fmt.Fprintf(out, "     %s\n", ui.cmd("expose server"))

	if strings.TrimSpace(a.GeneratedKey) != "" {
		_, _ = fmt.Fprintln(out, "  2) Login client (API key was generated and saved to .env)")
		_, _ = fmt.Fprintf(out, "     %s\n", ui.cmd(fmt.Sprintf("expose login --server %s --api-key %s", a.BaseDomain, a.GeneratedKey)))
	} else {
		_, _ = fmt.Fprintln(out, "  2) Create API key, then login client")
		_, _ = fmt.Fprintf(out, "     %s\n", ui.cmd("expose apikey create --name default"))
		_, _ = fmt.Fprintf(out, "     %s\n", ui.cmd(fmt.Sprintf("expose login --server %s --api-key <PASTE_KEY>", a.BaseDomain)))
	}
	_, _ = fmt.Fprintln(out, "  3) Expose a local app")
	_, _ = fmt.Fprintf(out, "     %s\n", ui.cmd("expose http 3000"))
}
