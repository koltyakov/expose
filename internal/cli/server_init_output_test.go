package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintInitNextSteps(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	printInitNextSteps(&out, serverInitAnswers{
		BaseDomain:   "https://example.com",
		GeneratedKey: "key_123",
	})
	got := out.String()
	for _, want := range []string{"Next Steps", "expose server", "expose login --server https://example.com --api-key key_123", "expose http 3000"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output %q", want, got)
		}
	}

	out.Reset()
	printInitNextSteps(&out, serverInitAnswers{BaseDomain: "https://example.com"})
	got = out.String()
	for _, want := range []string{"expose apikey create --name default", "expose login --server https://example.com --api-key <PASTE_KEY>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output %q", want, got)
		}
	}
}
