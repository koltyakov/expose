// Package selfupdate checks for newer releases on GitHub and replaces
// the running binary in-place.
package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// GitHubRepo is the owner/repo path used to query the GitHub API.
	GitHubRepo = "koltyakov/expose"
	// releasesURL is the GitHub API endpoint for the latest release.
	releasesURL = "https://api.github.com/repos/" + GitHubRepo + "/releases/latest"
)

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

// fetchLatestRelease calls the GitHub releases API.
func fetchLatestRelease(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release JSON: %w", err)
	}
	return &rel, nil
}

// assetNameForPlatform returns the expected archive file name
// matching the goreleaser naming template for the current OS/arch.
func assetNameForPlatform() (string, error) {
	osName, err := goosToAssetOS(runtime.GOOS)
	if err != nil {
		return "", err
	}
	archName, err := goarchToAssetArch(runtime.GOARCH)
	if err != nil {
		return "", err
	}

	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("expose_%s_%s%s", osName, archName, ext), nil
}

func goosToAssetOS(goos string) (string, error) {
	switch goos {
	case "darwin":
		return "Darwin", nil
	case "linux":
		return "Linux", nil
	case "windows":
		return "Windows", nil
	default:
		return "", fmt.Errorf("unsupported OS: %s", goos)
	}
}

func goarchToAssetArch(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", goarch)
	}
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %s", resp.Status)
	}

	// Limit to 100 MB to be safe.
	return io.ReadAll(io.LimitReader(resp.Body, 100<<20))
}

// extractBinary pulls the "expose" (or "expose.exe") binary out of the
// downloaded archive.
func extractBinary(assetName string, data []byte) ([]byte, error) {
	binaryName := "expose"
	if strings.HasSuffix(assetName, ".zip") {
		binaryName = "expose.exe"
		return extractFromZip(data, binaryName)
	}
	return extractFromTarGz(data, binaryName)
}

func extractFromTarGz(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == name && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", name)
}

func extractFromZip(data []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", name)
}

// replaceBinary atomically replaces the current executable with newBinary.
// It writes to a temp file next to the original, then renames.
func replaceBinary(newBinary []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determine executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}

	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, "expose-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // clean up on failure

	if _, err := tmp.Write(newBinary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Preserve the original file permissions.
	info, err := os.Stat(exe)
	if err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, info.Mode()); err != nil {
		return err
	}

	// On most systems we can rename over the running binary.
	if err := os.Rename(tmpPath, exe); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// isNewer returns true when latest > current using simple semver comparison.
// Both strings should already have the "v" prefix stripped.
func isNewer(current, latest string) bool {
	cp := parseSemver(current)
	lp := parseSemver(latest)
	if cp == nil || lp == nil {
		// Fall back to string comparison if parsing fails.
		return latest > current
	}
	if lp[0] != cp[0] {
		return lp[0] > cp[0]
	}
	if lp[1] != cp[1] {
		return lp[1] > cp[1]
	}
	return lp[2] > cp[2]
}

func parseSemver(v string) []int {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	nums := make([]int, 3)
	for i, p := range parts {
		// Strip pre-release suffix (e.g. "0-rc1") for comparison.
		p = strings.SplitN(p, "-", 2)[0]
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return nil
			}
			n = n*10 + int(ch-'0')
		}
		nums[i] = n
	}
	return nums
}
