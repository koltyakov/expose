package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

type pubUploadOptions struct {
	Folder, Endpoint, Server, Key, Name, SourceID string
	TTL                                           time.Duration
	Full, SkipUnchanged                           bool
	ExpectedSiteID                                string
	Progress                                      *pubProgress
	OnDiff                                        func(publish.FileDiff)
}

type pubUploadResult struct {
	Site     domain.PublishedSite
	Files    []domain.PublishedFile
	Diff     publish.FileDiff
	Uploaded bool
}

type pubHTTPError struct {
	status          int
	operation, text string
}

func (e pubHTTPError) Error() string {
	prefix := ""
	if e.operation != "" {
		prefix = e.operation + ": "
	}
	return fmt.Sprintf("%sserver returned %d %s: %s", prefix, e.status, http.StatusText(e.status), e.text)
}

// uploadPublishedSite is shared by one-shot publishing and watch updates.
func uploadPublishedSite(ctx context.Context, client *http.Client, opts pubUploadOptions) (pubUploadResult, error) {
	var result pubUploadResult
	progress := opts.Progress
	if progress != nil {
		defer progress.close()
	}
	query := url.Values{}
	if opts.Name != "" {
		query.Set("domain", opts.Name)
	}
	query.Set("source_id", opts.SourceID)
	if opts.TTL > 0 {
		query.Set("ttl", opts.TTL.String())
	}
	if opts.ExpectedSiteID != "" {
		query.Set("site_id", opts.ExpectedSiteID)
	}
	var remote []domain.PublishedFile
	var revision string
	var err error
	if !opts.Full {
		if progress != nil {
			progress.start("Comparing local files with the published site...")
		}
		remote, revision, err = fetchPublishedFiles(ctx, client, opts.Endpoint, opts.Key, opts.Name, opts.SourceID)
		if err != nil {
			return result, err
		}
		result.Files, err = publish.Manifest(opts.Folder)
		if err != nil {
			return result, err
		}
		result.Diff, err = publish.DiffFiles(result.Files, remote)
		if err != nil {
			return result, err
		}
		if opts.OnDiff != nil {
			opts.OnDiff(result.Diff)
		}
		if progress != nil {
			progress.finish(pubChangeSummary(result.Diff) + "\n")
		}
		if opts.SkipUnchanged && len(result.Diff.Changed) == 0 && result.Diff.Deleted == 0 {
			return result, nil
		}
		query.Set("incremental", "true")
	}
	archive, err := os.CreateTemp("", "expose-publish-*.tar.gz")
	if err != nil {
		return result, err
	}
	defer func() { _ = os.Remove(archive.Name()) }()
	defer func() { _ = archive.Close() }()
	var report func(publish.ArchiveProgress)
	var stats publish.ArchiveProgress
	archiveStarted := time.Now()
	if progress != nil {
		progress.start(fmt.Sprintf("Archiving %s...", opts.Folder))
		report = func(p publish.ArchiveProgress) {
			stats = p
			progress.update(fmt.Sprintf("Archiving: %d / %d files, %s / %s", p.Files, p.TotalFiles, pubFormatBytes(float64(p.Bytes)), pubFormatBytes(float64(p.TotalBytes))))
		}
	}
	limited := &archiveLimitWriter{w: archive, remaining: publish.MaxArchiveBytes, ctx: ctx}
	if opts.Full {
		err = publish.ArchiveWithProgress(opts.Folder, limited, report)
	} else {
		err = publish.ArchiveDelta(opts.Folder, limited, result.Files, remote, report)
	}
	if err != nil {
		return result, err
	}
	info, err := archive.Stat()
	if err != nil {
		return result, err
	}
	archiveSize := info.Size()
	if progress != nil {
		files := "files"
		if stats.Files == 1 {
			files = "file"
		}
		progress.finish(fmt.Sprintf("Archived %d %s, %s → %s tar.gz in %s", stats.Files, files, pubFormatBytes(float64(stats.Bytes)), pubFormatBytes(float64(archiveSize)), time.Since(archiveStarted).Round(time.Millisecond)))
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.Endpoint+"?"+query.Encode(), archive)
	if err != nil {
		return result, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.Key)
	req.Header.Set("Content-Type", "application/gzip")
	req.ContentLength = archiveSize
	if !opts.Full {
		req.Header.Set("If-Match", revision)
	}
	uploadStarted := time.Now()
	if progress != nil {
		progress.start(fmt.Sprintf("Uploading %s to %s...", pubFormatBytes(float64(archiveSize)), opts.Server))
		req.Body = io.NopCloser(&pubUploadReader{r: archive, progress: progress, total: archiveSize})
	}
	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		text, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return result, pubHTTPError{status: resp.StatusCode, text: strings.TrimSpace(string(text))}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&result.Site); err != nil {
		return result, err
	}
	if result.Site.ID == "" || result.Site.Hostname == "" {
		return result, fmt.Errorf("server returned invalid publication metadata")
	}
	if opts.ExpectedSiteID != "" && result.Site.ID != opts.ExpectedSiteID {
		return result, fmt.Errorf("publication identity changed while watching")
	}
	result.Uploaded = true
	if progress != nil {
		progress.finish(fmt.Sprintf("Uploaded %s (100%%) in %s", pubFormatBytes(float64(archiveSize)), time.Since(uploadStarted).Round(time.Millisecond)))
	}
	return result, nil
}
