package cli

import (
	"fmt"
	"io"
	"strings"
)

type wizardTUI struct {
	color bool
}

func newWizardTUI() wizardTUI {
	return wizardTUI{color: isInteractiveOutput()}
}

func (w wizardTUI) styled(code, text string) string {
	if !w.color {
		return text
	}
	return code + text + upANSIReset
}

func (w wizardTUI) heading(text string) string {
	return w.styled(upANSIBold+upANSICyan, text)
}

func (w wizardTUI) dim(text string) string {
	return w.styled(upANSIDim, text)
}

func (w wizardTUI) ok(text string) string {
	return w.styled(upANSIGreen, text)
}

func (w wizardTUI) err(text string) string {
	return w.styled(upANSIRed, text)
}

func (w wizardTUI) cmd(text string) string {
	return w.styled(upANSIBold+upANSICyan, text)
}

func (w wizardTUI) printBanner(out io.Writer, title, subtitle string) {
	title = strings.TrimSpace(title)
	subtitle = strings.TrimSpace(subtitle)
	if title != "" {
		_, _ = fmt.Fprintf(out, "%s %s\n", w.styled(upANSICyan, "◆"), w.heading(title))
	}
	if subtitle != "" {
		_, _ = fmt.Fprintf(out, "  %s\n", w.dim(subtitle))
	}
	_, _ = fmt.Fprintln(out)
}

func (w wizardTUI) printSection(out io.Writer, title string) {
	title = strings.TrimSpace(title)
	if title == "" {
		return
	}
	_, _ = fmt.Fprintf(out, "%s %s\n", w.styled(upANSICyan, "▸"), w.heading(title))
}

func (w wizardTUI) printQuestion(out io.Writer, title, details, sample string) {
	_, _ = fmt.Fprintf(out, "%s %s\n", w.styled(upANSICyan, "●"), w.heading(strings.TrimSpace(title)))
	if strings.TrimSpace(details) != "" {
		_, _ = fmt.Fprintf(out, "  %s\n", w.dim(strings.TrimSpace(details)))
	}
	if strings.TrimSpace(sample) != "" {
		_, _ = fmt.Fprintf(out, "  %s\n", w.dim(strings.TrimSpace(sample)))
	}
}

func (w wizardTUI) promptLabel(label string) string {
	return w.styled(upANSIBold, label)
}

func (w wizardTUI) printInvalid(out io.Writer, msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		msg = "invalid input"
	}
	_, _ = fmt.Fprintf(out, "  %s %s %s\n\n", w.err("!"), w.err("Invalid value:"), msg)
}
