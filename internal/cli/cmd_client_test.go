package cli

import (
	"context"
	"testing"
)

func TestRunStaticRejectsInvalidDomain(t *testing.T) {
	t.Parallel()

	code := runStatic(context.Background(), []string{"--domain", "incorrect one"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid static domain, got %d", code)
	}
}

func TestRunClientRejectsMissingPort(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("EXPOSE_DOMAIN", "")
	t.Setenv("EXPOSE_API_KEY", "")
	t.Setenv("EXPOSE_PORT", "")

	code := runClient(context.Background(), nil)
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing client port, got %d", code)
	}
}
