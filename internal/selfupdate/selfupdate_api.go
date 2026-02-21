package selfupdate

import (
	"context"
	"fmt"
	"net/http"
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

var releaseHTTPClient = &http.Client{Timeout: 20 * time.Second}
var downloadHTTPClient = &http.Client{Timeout: 5 * time.Minute}

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

	data, err := download(ctx, dlURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", assetName, err)
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
