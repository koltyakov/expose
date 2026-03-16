package cli

import (
	"context"
	"testing"
)

func TestRunServerRejectsMissingDomain(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("EXPOSE_DOMAIN", "")

	code := runServer(context.Background(), nil)
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing server domain, got %d", code)
	}
}
