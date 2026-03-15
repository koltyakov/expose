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
