package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func runServerVersion(ctx context.Context, args []string) int {
	if err := serverVersionCommand(ctx, args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) || (errors.Is(err, context.Canceled) && ctx.Err() != nil) {
			return 0
		}
		fmt.Fprintln(os.Stderr, "server version error:", err)
		return 1
	}
	return 0
}

func serverVersionCommand(ctx context.Context, args []string, out io.Writer) error {
	preServer, preKey := capturePreDotEnv()
	dotEnv := loadClientEnvFromDotEnv(".env")
	cfg := config.ClientConfig{ServerURL: envOr("EXPOSE_DOMAIN", ""), APIKey: envOr("EXPOSE_API_KEY", "")}
	fs := flag.NewFlagSet("server version", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage: expose server version [--profile NAME] [--server URL] [--api-key KEY]")
		_, _ = fmt.Fprintln(fs.Output(), "Print the running server's version using your saved login or explicit credentials.")
	}
	fs.StringVar(&cfg.Profile, "profile", "", "Saved login profile (default when omitted)")
	fs.StringVar(&cfg.ServerURL, "server", cfg.ServerURL, "Server URL")
	fs.StringVar(&cfg.APIKey, "api-key", cfg.APIKey, "API key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("server version takes no positional arguments")
	}
	if err := resolveClientCredentials(ctx, &cfg, captureClientCredSources(args, dotEnv, preServer, preKey)); err != nil {
		return err
	}
	server, err := normalizeServerURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	endpoint, err := url.JoinPath(server, serviceapi.Version)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return errors.New("server does not support version lookups; update the server to use expose server version")
	case http.StatusUnauthorized:
		return errors.New("unauthorized; check your API key or run expose login")
	default:
		return fmt.Errorf("server returned %s", resp.Status)
	}

	const maxResponseBytes = 4096
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read server version response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return errors.New("server version response is too large")
	}
	var result serviceapi.VersionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decode server version response: %w", err)
	}
	if result.Version == "" || strings.ContainsFunc(result.Version, func(r rune) bool {
		return !unicode.IsPrint(r) || unicode.IsSpace(r)
	}) {
		return errors.New("server returned an invalid version")
	}
	_, err = fmt.Fprintln(out, result.Version)
	return err
}
