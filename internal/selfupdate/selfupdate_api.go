// Package selfupdate checks for newer releases on GitHub and replaces
// the running binary in-place.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	// GitHubRepo is the owner/repo path used to query the GitHub API.
	GitHubRepo = "koltyakov/expose"
	// releasesURL is the GitHub API endpoint for the latest release.
	releasesURL      = "https://api.github.com/repos/" + GitHubRepo + "/releases/latest"
	maxReleaseJSON   = 2 << 20   // 2 MiB
	maxDownloadBytes = 100 << 20 // 100 MiB
	maxBinaryBytes   = 100 << 20 // 100 MiB
)

var releaseHTTPClient = &http.Client{Timeout: 20 * time.Second, CheckRedirect: githubAPIRedirect}
var downloadHTTPClient = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: assetRedirect}

// allowedAssetHosts lists the only hosts release artifacts (archives and the
// checksum manifest) may be downloaded from. Release metadata comes from the
// GitHub API, and browser_download_url values point at github.com, which
// redirects to a *.githubusercontent.com storage host.
var allowedAssetHosts = []string{
	"github.com",
	"githubusercontent.com",
}

// maxRedirects caps the redirect chain at the net/http default limit.
const maxRedirects = 10

// httpsOnlyRedirect rejects redirect hops that would downgrade a request from
// HTTPS to plain HTTP.
func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("stopped after 10 redirects")
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("refusing redirect to non-HTTPS URL %q", req.URL.Redacted())
	}
	return nil
}

func githubAPIRedirect(req *http.Request, via []*http.Request) error {
	if err := httpsOnlyRedirect(req, via); err != nil {
		return err
	}
	if !strings.EqualFold(req.URL.Hostname(), "api.github.com") {
		return fmt.Errorf("refusing GitHub API redirect to untrusted host %q", req.URL.Hostname())
	}
	return nil
}

func assetRedirect(req *http.Request, via []*http.Request) error {
	if err := httpsOnlyRedirect(req, via); err != nil {
		return err
	}
	return validateAssetURLStrict(req.URL.String())
}

// validateAssetURL checks that a release artifact URL uses HTTPS and targets
// an allowlisted GitHub host. It is a variable so tests can substitute
// plain-HTTP httptest servers.
var validateAssetURL = validateAssetURLStrict

func validateAssetURLStrict(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid download URL %q: %w", rawURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("refusing non-HTTPS download URL %q", u.Redacted())
	}
	host := strings.ToLower(u.Hostname())
	for _, allowed := range allowedAssetHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return nil
		}
	}
	return fmt.Errorf("download host %q is not in the allowlist %v", host, allowedAssetHosts)
}

// Release holds the subset of GitHub release metadata we care about.
type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a single downloadable file attached to a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Result describes what happened during an update check.
type Result struct {
	CurrentVersion string
	LatestVersion  string
	Updated        bool
	AssetName      string
}

// Check queries GitHub for the latest release and returns the release
// metadata. Returns nil when the current version is already up to date.
func Check(ctx context.Context, currentVersion string) (*Release, error) {
	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		return nil, err
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")
	if current == latest || current == "dev" {
		return nil, nil // already up to date or dev build
	}
	if !isNewer(current, latest) {
		return nil, nil
	}
	return rel, nil
}

// Apply downloads the appropriate asset from the release and replaces the
// current binary. The caller should have already confirmed the user wants
// to proceed.
func Apply(ctx context.Context, rel *Release) (*Result, error) {
	assetName, err := assetNameForPlatform()
	if err != nil {
		return nil, err
	}

	var dlURL string
	for _, a := range rel.Assets {
		if a.Name == assetName {
			dlURL = a.BrowserDownloadURL
			break
		}
	}
	if dlURL == "" {
		return nil, fmt.Errorf("no release asset %q found for %s/%s", assetName, runtime.GOOS, runtime.GOARCH)
	}
	if err := validateAssetURL(dlURL); err != nil {
		return nil, fmt.Errorf("download %s: %w", assetName, err)
	}

	data, err := download(ctx, dlURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", assetName, err)
	}
	if err := verifyAssetChecksum(ctx, rel, assetName, data); err != nil {
		return nil, fmt.Errorf("verify %s: %w", assetName, err)
	}

	binary, err := extractBinary(assetName, data)
	if err != nil {
		return nil, fmt.Errorf("extract binary: %w", err)
	}

	if err := replaceBinary(binary); err != nil {
		return nil, fmt.Errorf("replace binary: %w", err)
	}

	return &Result{
		LatestVersion: strings.TrimPrefix(rel.TagName, "v"),
		Updated:       true,
		AssetName:     assetName,
	}, nil
}

// CheckAndApply is a convenience wrapper that checks for a newer release and,
// if one is available, downloads and applies it in a single step.
func CheckAndApply(ctx context.Context, currentVersion string) (*Result, error) {
	rel, err := Check(ctx, currentVersion)
	if err != nil {
		return nil, err
	}
	if rel == nil {
		return &Result{CurrentVersion: currentVersion, Updated: false}, nil
	}
	result, err := Apply(ctx, rel)
	if err != nil {
		return nil, err
	}
	result.CurrentVersion = currentVersion
	return result, nil
}

// Restart re-executes the current binary with the original arguments and
// environment. On success this function does not return (the process image
// is replaced). On failure it returns an error.
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determine executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
