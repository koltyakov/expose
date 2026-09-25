package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

func runPub(ctx context.Context, args []string) int {
	if err := pubCommand(ctx, args); err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return 0
		}
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintln(os.Stderr, "pub error:", err)
		return 1
	}
	return 0
}

func pubCommand(ctx context.Context, args []string) error {
	action := "upload"
	if len(args) > 0 {
		switch args[0] {
		case "list", "delete", "connect":
			action, args = args[0], args[1:]
		}
	}
	// Accept both `pub ./dist --ttl 24h` and flags before the folder.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		args = append(append([]string{}, args[1:]...), args[0])
	}
	preServer, preKey := capturePreDotEnv()
	dotEnv := loadClientEnvFromDotEnv(".env")
	fs := flag.NewFlagSet("pub "+action, flag.ContinueOnError)
	if action == "delete" || action == "connect" {
		fs.Usage = func() {
			_, _ = fmt.Fprintf(fs.Output(), "Usage: expose pub %s <folder> | --domain=<subdomain> [--server URL] [--api-key KEY] [--json]\n", action)
			if action == "connect" {
				_, _ = fmt.Fprintln(fs.Output(), "Show live hosting stats. Ctrl+C disconnects and leaves the site hosted. --json streams snapshots as NDJSON.")
			} else {
				_, _ = fmt.Fprintln(fs.Output(), "Deletes the published files and releases the hostname. Find subdomains with `expose pub list`.")
			}
			fs.PrintDefaults()
		}
	}
	cfg := config.ClientConfig{ServerURL: envOr("EXPOSE_DOMAIN", ""), APIKey: envOr("EXPOSE_API_KEY", "")}
	var name string
	var ttl time.Duration
	var jsonOutput bool
	fs.StringVar(&cfg.ServerURL, "server", cfg.ServerURL, "Server URL")
	fs.StringVar(&cfg.APIKey, "api-key", cfg.APIKey, "API key")
	fs.StringVar(&name, "domain", "", "Public subdomain label; defaults to a persistent random hash")
	fs.DurationVar(&ttl, "ttl", 0, "Delete the site after this duration, e.g. 24h; defaults to 7 days on the server")
	fs.BoolVar(&jsonOutput, "json", false, "Print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if action == "list" {
		if fs.NArg() != 0 {
			return fmt.Errorf("list takes no positional arguments")
		}
	} else if action == "delete" || action == "connect" {
		byFolder := fs.NArg() == 1 && name == ""
		byDomain := fs.NArg() == 0 && strings.TrimSpace(name) != ""
		if !byFolder && !byDomain {
			return fmt.Errorf("provide a folder or --domain, e.g. `expose pub %s ./dist` or `expose pub %s --domain=docs`; find domains with `expose pub list`", action, action)
		}
	} else if fs.NArg() != 1 {
		return fmt.Errorf("expected a folder to publish")
	}
	if ttl < 0 || (cliFlagPassed(args, "ttl") && ttl == 0) {
		return fmt.Errorf("ttl must be positive")
	}
	if action != "upload" && cliFlagPassed(args, "ttl") {
		return fmt.Errorf("ttl is only supported when uploading")
	}
	if name != "" {
		name = strings.ToLower(strings.TrimSpace(name))
		if err := config.ValidateTunnelSubdomain(name); err != nil {
			return err
		}
	}
	if action == "list" && name != "" {
		return fmt.Errorf("--domain is not supported when listing")
	}
	var sourceID string
	if action == "upload" || ((action == "delete" || action == "connect") && fs.NArg() == 1) {
		var err error
		sourceID, err = publishedFolderID(fs.Arg(0))
		if err != nil {
			return err
		}
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
	endpoint := strings.TrimRight(server, "/") + "/v1/sites"
	client := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if action == "connect" {
		client.Timeout = 10 * time.Second
	}
	siteTarget := name
	if (action == "delete" || action == "connect") && sourceID != "" {
		var site domain.PublishedSite
		site, err = publishedFolderSite(ctx, client, endpoint, cfg.APIKey, sourceID)
		if err != nil {
			return err
		}
		name, _, _ = strings.Cut(site.Hostname, ".")
		siteTarget = site.ID
	}
	if action == "connect" {
		return connectPublishedSite(ctx, client, endpoint, cfg.APIKey, siteTarget, os.Stdout, isInteractiveOutput(), jsonOutput, time.Second)
	}
	query := url.Values{}
	if action == "upload" && name != "" {
		query.Set("domain", name)
	}
	if action == "upload" {
		query.Set("source_id", sourceID)
	}
	if ttl > 0 {
		query.Set("ttl", ttl.String())
	}
	method := http.MethodGet
	var body io.Reader
	var archive *os.File
	switch action {
	case "upload":
		archive, err = os.CreateTemp("", "expose-publish-*.tar.gz")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(archive.Name()) }()
		defer func() { _ = archive.Close() }()
		if err := publish.ArchiveWithWarnings(fs.Arg(0), &archiveLimitWriter{w: archive, remaining: publish.MaxArchiveBytes}, func(name string, reason error) {
			fmt.Fprintf(os.Stderr, "Warning: ignored %q: %v\n", name, reason)
		}); err != nil {
			return err
		}
		if _, err := archive.Seek(0, io.SeekStart); err != nil {
			return err
		}
		method, body = http.MethodPost, archive
	case "delete":
		endpoint += "/" + url.PathEscape(siteTarget)
		method = http.MethodDelete
	}
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	if archive != nil {
		req.Header.Set("Content-Type", "application/gzip")
		info, err := archive.Stat()
		if err != nil {
			return err
		}
		req.ContentLength = info.Size()
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		text, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("server returned %s: %s", resp.Status, strings.TrimSpace(string(text)))
	}
	if action == "delete" {
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(struct {
				Subdomain   string `json:"subdomain"`
				Unpublished bool   `json:"unpublished"`
			}{Subdomain: name, Unpublished: true})
		}
		fmt.Printf("Unpublished %s. Files deleted and hostname released.\n", name)
		return nil
	}
	var sites []domain.PublishedSite
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 8<<20))
	if action == "list" {
		if err := decoder.Decode(&sites); err != nil {
			return err
		}
	} else {
		var site domain.PublishedSite
		if err := decoder.Decode(&site); err != nil {
			return err
		}
		sites = append(sites, site)
	}
	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if action == "list" {
			return encoder.Encode(sites)
		}
		return encoder.Encode(sites[0])
	}
	if len(sites) == 0 {
		fmt.Println("No published sites.")
	}
	for _, site := range sites {
		expiry := "no expiry"
		if site.ExpiresAt != nil {
			expiry = "expires " + site.ExpiresAt.Format(time.RFC3339)
		}
		subdomain, _, _ := strings.Cut(site.Hostname, ".")
		fmt.Printf("%s  https://%s  %s\n", subdomain, site.Hostname, expiry)
	}
	return nil
}

// publishedFolderID associates a publication with its source without uploading
// the local path or writing a tracking file into the build output.
func publishedFolderID(folder string) (string, error) {
	root, err := resolveStaticRoot(folder)
	if err != nil {
		return "", fmt.Errorf("invalid publish folder: %w; use --domain to select a subdomain", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(client.ResolveMachineID(hostname) + "\x00" + root))
	return fmt.Sprintf("%x", sum), nil
}

func publishedFolderSite(ctx context.Context, client *http.Client, endpoint, key, sourceID string) (domain.PublishedSite, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.PublishedSite{}, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return domain.PublishedSite{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return domain.PublishedSite{}, fmt.Errorf("list published sites: server returned %s", resp.Status)
	}
	var sites []domain.PublishedSite
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&sites); err != nil {
		return domain.PublishedSite{}, err
	}
	var match domain.PublishedSite
	for _, site := range sites {
		if site.SourceID != sourceID {
			continue
		}
		if match.ID != "" {
			return domain.PublishedSite{}, fmt.Errorf("multiple publications match this folder; select one with --domain")
		}
		match = site
	}
	if match.ID == "" {
		return match, fmt.Errorf("no publication found for this folder; use `expose pub list` and select a site with --domain")
	}
	return match, nil
}

type archiveLimitWriter struct {
	w         io.Writer
	remaining int64
}

func (w *archiveLimitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("compressed archive exceeds 100 MiB")
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}
