package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestWizardTUIStyledVariants(t *testing.T) {
	t.Parallel()

	ui := wizardTUI{color: true}

	if got := ui.ok("done"); !strings.Contains(got, upANSIGreen) || !strings.Contains(got, upANSIReset) {
		t.Fatalf("ok() = %q, expected ANSI styling", got)
	}
	if got := ui.err("bad"); !strings.Contains(got, upANSIRed) {
		t.Fatalf("err() = %q, expected red ANSI styling", got)
	}
	if got := ui.cmd("expose up"); !strings.Contains(got, upANSIBold+upANSICyan) {
		t.Fatalf("cmd() = %q, expected command styling", got)
	}
}

func TestWizardTUIPrintHelpersWithoutColor(t *testing.T) {
	t.Parallel()

	ui := wizardTUI{color: false}
	var out bytes.Buffer

	ui.printBanner(&out, " Setup ", " Guided mode ")
	ui.printSection(&out, "Next")
	ui.printQuestion(&out, "TLS mode", "Pick one.", "dynamic or wildcard")
	ui.printInvalid(&out, "")

	got := out.String()
	for _, want := range []string{"Setup", "Guided mode", "Next", "TLS mode", "Pick one.", "dynamic or wildcard", "invalid input"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output %q", want, got)
		}
	}

	out.Reset()
	ui.printSection(&out, "   ")
	if out.Len() != 0 {
		t.Fatalf("expected blank section title to render nothing, got %q", out.String())
	}

	if got := ui.promptLabel("Value"); got != "Value" {
		t.Fatalf("promptLabel() = %q, want %q", got, "Value")
	}
}
