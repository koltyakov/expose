package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/serviceapi"
	"github.com/koltyakov/expose/internal/termui"
	"golang.org/x/term"
)

func runList(ctx context.Context, args []string) int {
	if err := listCommand(ctx, args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) || (errors.Is(err, context.Canceled) && ctx.Err() != nil) {
			return 0
		}
		fmt.Fprintln(os.Stderr, "list error:", err)
		return 1
	}
	return 0
}

func listCommand(ctx context.Context, args []string, out io.Writer) error {
	preServer, preKey := capturePreDotEnv()
	dotEnv := loadClientEnvFromDotEnv(".env")
	cfg := config.ClientConfig{ServerURL: envOr("EXPOSE_DOMAIN", ""), APIKey: envOr("EXPOSE_API_KEY", "")}
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage: expose list [--server URL] [--api-key KEY] [--json]")
		_, _ = fmt.Fprintln(fs.Output(), "List your tunnels and published sites, including retained disconnected hostnames.")
		fs.PrintDefaults()
	}
	var jsonOutput bool
	fs.StringVar(&cfg.ServerURL, "server", cfg.ServerURL, "Server URL")
	fs.StringVar(&cfg.APIKey, "api-key", cfg.APIKey, "API key")
	fs.BoolVar(&jsonOutput, "json", false, "Print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("list takes no positional arguments")
	}
	if err := resolveClientCredentials(ctx, &cfg, captureClientCredSources(args, dotEnv, preServer, preKey)); err != nil {
		return err
	}
	server, err := normalizeServerURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("API key is required; run expose login")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(server, "/")+serviceapi.Exposures, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return fmt.Errorf("server does not support exposure listing; update the server to use expose list")
		case http.StatusUnauthorized:
			return fmt.Errorf("unauthorized; check your API key or run expose login")
		default:
			return fmt.Errorf("list exposures: server returned %s", resp.Status)
		}
	}
	exposures := []domain.Exposure{}
	if err := json.NewDecoder(resp.Body).Decode(&exposures); err != nil {
		return fmt.Errorf("decode exposure list: %w", err)
	}
	if jsonOutput {
		return json.NewEncoder(out).Encode(exposures)
	}
	color, columns := false, 0
	if f, ok := out.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		color = os.Getenv("NO_COLOR") == ""
		columns = termui.TerminalColumnsForWriter(out)
	}
	return writeExposureList(out, exposures, color, columns)
}
