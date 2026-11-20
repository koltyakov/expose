package cli

import (
	"context"
	"flag"
	"testing"

	"github.com/koltyakov/expose/internal/config"
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

func TestClientOutputFlagsReachClientConfig(t *testing.T) {
	t.Setenv("EXPOSE_LOG_LEVEL", "warn")
	t.Setenv("EXPOSE_LOG_REQUESTS", "")
	t.Setenv("EXPOSE_LOG_FORMAT", "")

	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	output := registerClientOutputFlags(fs)
	if err := fs.Parse([]string{"--json", "--log-requests=false"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseClientFlags(append([]string{"--port", "3000"}, output.args()...))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "warn" || cfg.LogFormat != "json" || !cfg.OmitRequestLogs {
		t.Fatalf("http config: level=%q format=%q omit=%v", cfg.LogLevel, cfg.LogFormat, cfg.OmitRequestLogs)
	}

	var static config.ClientConfig
	output.apply(&static)
	if static.LogLevel != "warn" || static.LogFormat != "json" || !static.OmitRequestLogs {
		t.Fatalf("static config: level=%q format=%q omit=%v", static.LogLevel, static.LogFormat, static.OmitRequestLogs)
	}
}
