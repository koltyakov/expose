package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/termui"
)

const pubChangeHeading = "Changes (incremental):"

type pubChangeStat struct {
	label string
	count int
	bytes int64
}

func pubChangeRows(diff publish.FileDiff) []pubChangeStat {
	return []pubChangeStat{
		{"New", diff.Added, diff.AddedBytes},
		{"Updated", diff.Updated, diff.UpdatedBytes},
		{"Deleted", diff.Deleted, diff.DeletedBytes},
		{"Unchanged", diff.Unchanged, diff.UnchangedBytes},
	}
}

func pubChangeSummary(diff publish.FileDiff) string {
	var b strings.Builder
	b.WriteString(pubChangeHeading)
	for _, row := range pubChangeRows(diff) {
		fmt.Fprintf(&b, "\n  %-9s  %5d %-5s  %s", row.label, row.count, termui.Pluralize(row.count, "file"), pubFormatBytes(float64(row.bytes)))
	}
	return b.String()
}

func fetchPublishedFiles(ctx context.Context, client *http.Client, endpoint, key, name, sourceID string) ([]domain.PublishedFile, string, error) {
	query := url.Values{}
	if name != "" {
		query.Set("domain", name)
	}
	query.Set("source_id", sourceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/files?"+query.Encode(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return nil, "", fmt.Errorf("server does not support incremental publishing; upgrade the server or use --full")
		}
		text, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", pubHTTPError{status: resp.StatusCode, operation: "list published files", text: strings.TrimSpace(string(text))}
	}
	revision := resp.Header.Get("ETag")
	if len(revision) < 2 || !strings.HasPrefix(revision, `"`) || !strings.HasSuffix(revision, `"`) {
		return nil, "", fmt.Errorf("server did not provide an incremental publication revision; upgrade the server or use --full")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, publish.MaxManifestBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > publish.MaxManifestBytes {
		return nil, "", fmt.Errorf("published file manifest exceeds %d MiB", publish.MaxManifestBytes>>20)
	}
	var files []domain.PublishedFile
	if err := json.Unmarshal(data, &files); err != nil {
		return nil, "", fmt.Errorf("invalid published file manifest: %w", err)
	}
	return files, revision, nil
}
