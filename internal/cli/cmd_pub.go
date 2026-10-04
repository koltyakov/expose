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
	"github.com/koltyakov/expose/internal/serviceapi"
	"golang.org/x/term"
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
	var full bool
	var watch bool
	var staged bool
	var ws bool
	fs.StringVar(&cfg.ServerURL, "server", cfg.ServerURL, "Server URL")
	fs.StringVar(&cfg.APIKey, "api-key", cfg.APIKey, "API key")
	fs.StringVar(&name, "domain", "", "Public subdomain label; defaults to a persistent random hash")
	fs.DurationVar(&ttl, "ttl", 0, "Delete the site after this duration, e.g. 24h; defaults to 7 days on the server")
	fs.BoolVar(&jsonOutput, "json", false, "Print JSON")
	fs.BoolVar(&full, "full", false, "Upload all public files without fetching a file list or comparing checksums")
	fs.BoolVar(&watch, "watch", false, "Watch local files, publish changes, and show live hosting stats")
	fs.BoolVar(&staged, "staged", false, "With --watch, publish only Git-staged changes using staged file contents")
	fs.BoolVar(&ws, "ws", false, "Inject a WebSocket heartbeat to track open pages in hosting stats")
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
	if action != "upload" && cliFlagPassed(args, "full") {
		return fmt.Errorf("full is only supported when uploading")
	}
	if action != "upload" && cliFlagPassed(args, "ws") {
		return fmt.Errorf("ws is only supported when uploading")
	}
	if action != "upload" && cliFlagPassed(args, "watch") {
		return fmt.Errorf("watch is only supported when uploading")
	}
	if watch && full {
		return fmt.Errorf("--watch publishes incremental changes and cannot be combined with --full")
	}
	if cliFlagPassed(args, "staged") && (action != "upload" || !watch) {
		return fmt.Errorf("--staged requires --watch when uploading")
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
	endpoint := strings.TrimRight(server, "/") + serviceapi.Sites
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
	if action == "upload" {
		opts := pubUploadOptions{Folder: fs.Arg(0), Endpoint: endpoint, Server: server, Key: cfg.APIKey, Name: name, SourceID: sourceID, TTL: ttl, Full: full, WS: ws}
		var snapshot map[string]os.FileInfo
		if watch {
			opts.IgnoreNewEmpty = true
			if staged {
				opts.Staged, err = newPubStagedWatch(ctx, opts.Folder)
				if err != nil {
					return err
				}
				defer opts.Staged.close()
			}
			snapshot, err = opts.watchSnapshot(ctx)
			if err != nil {
				return err
			}
		}
		if !jsonOutput {
			opts.Progress = &pubProgress{out: os.Stderr, interactive: term.IsTerminal(int(os.Stderr.Fd()))}
		}
		result, err := uploadPublishedSite(ctx, client, opts)
		if err != nil {
			return err
		}
		if watch {
			return watchPublishedSite(ctx, client, opts, result, snapshot, os.Stdout, term.IsTerminal(int(os.Stdout.Fd())), jsonOutput, pubWatchTiming{})
		}
		if jsonOutput {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(result.Site)
		}
		return writePublishedSiteResult(os.Stdout, result.Site, term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == "")
	}
	method := http.MethodGet
	if action == "delete" {
		endpoint += "/" + url.PathEscape(siteTarget)
		method = http.MethodDelete
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
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
	if err := decoder.Decode(&sites); err != nil {
		return err
	}
	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(sites)
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
	ctx       context.Context
}

func (w *archiveLimitWriter) Write(p []byte) (int, error) {
	if w.ctx != nil && w.ctx.Err() != nil {
		return 0, w.ctx.Err()
	}
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("compressed archive exceeds %d MiB", publish.MaxArchiveBytes>>20)
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}
