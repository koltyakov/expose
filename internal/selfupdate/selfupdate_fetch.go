package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// fetchLatestRelease calls the GitHub releases API.
func fetchLatestRelease(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "expose-selfupdate")

	resp, err := releaseHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	body, err := readAllWithLimit(resp.Body, maxReleaseJSON)
	if err != nil {
		return nil, fmt.Errorf("read release JSON: %w", err)
	}
	var rel Release
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("decode release JSON: %w", err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, errors.New("release metadata missing tag_name")
	}
	return &rel, nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "expose-selfupdate")
	resp, err := downloadHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %s", resp.Status)
	}
	if resp.ContentLength > maxDownloadBytes {
		return nil, fmt.Errorf("download too large: %d bytes exceeds limit %d", resp.ContentLength, maxDownloadBytes)
	}

	return readAllWithLimit(resp.Body, maxDownloadBytes)
}

func readAllWithLimit(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid read limit")
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("content exceeds limit of %d bytes", limit)
	}
	return data, nil
}
