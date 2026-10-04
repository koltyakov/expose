package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/termui"
)

type pubWatchTestOutput struct {
	bytes.Buffer
	onEvent func(pubWatchEvent)
	onText  func(string)
}

func (w *pubWatchTestOutput) Write(data []byte) (int, error) {
	n, err := w.Buffer.Write(data)
	if w.onText != nil {
		w.onText(string(data))
	}
	var event pubWatchEvent
	if json.Unmarshal(data, &event) == nil && w.onEvent != nil {
		w.onEvent(event)
	}
	return n, err
}

func (w *pubWatchTestOutput) WriteString(text string) (int, error) {
	return w.Write([]byte(text))
}

type pubWatchTestServer struct {
	mu                                       sync.Mutex
	dir                                      string
	files                                    []domain.PublishedFile
	site                                     domain.PublishedSite
	revision, posts, commits, fetches, stats int
	active, maxActive                        int
	failCount, failStatus, statsStatus       int
	block                                    <-chan struct{}
	onPost                                   func(int)
	finished                                 chan struct{}
}

func newPubWatchTestServer(t *testing.T, root string) (*pubWatchTestServer, *http.Client, pubUploadOptions, pubUploadResult, map[string]os.FileInfo) {
	t.Helper()
	h := &pubWatchTestServer{dir: t.TempDir(), site: domain.PublishedSite{ID: "site_watch", Hostname: "docs.example.com"}, finished: make(chan struct{}, 16)}
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	if err := publish.Extract(&archive, h.dir); err != nil {
		t.Fatal(err)
	}
	var err error
	h.files, err = publish.Manifest(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := publish.FileSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := publish.DiffFiles(h.files, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("watch request missing credentials")
		}
		if r.Method == http.MethodGet {
			h.mu.Lock()
			defer h.mu.Unlock()
			switch r.URL.Path {
			case "/_expose/v1/sites/files":
				h.fetches++
				w.Header().Set("ETag", strconv.Quote(fmt.Sprintf("rev-%d", h.revision)))
				_ = json.NewEncoder(w).Encode(h.files)
			case "/_expose/v1/sites/site_watch/stats":
				h.stats++
				if h.statsStatus != 0 {
					w.WriteHeader(h.statsStatus)
					return
				}
				_ = json.NewEncoder(w).Encode(domain.PublishedSiteStats{Site: h.site, CapturedAt: time.Now(), HTTPRequests: int64(h.stats), ResponseBytes: int64(h.stats * 1024)})
			default:
				t.Errorf("watch did not pin the stats identity: %s", r.URL.Path)
				http.NotFound(w, r)
			}
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/_expose/v1/sites" || r.URL.Query().Get("incremental") != "true" || r.URL.Query().Get("site_id") != h.site.ID {
			t.Errorf("unexpected watch mutation: %s %s", r.Method, r.URL)
			http.Error(w, "bad watch request", http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.posts++
		h.active++
		h.maxActive = max(h.maxActive, h.active)
		post := h.posts
		fail := post <= h.failCount
		h.mu.Unlock()
		defer func() {
			h.mu.Lock()
			h.active--
			h.mu.Unlock()
			select {
			case h.finished <- struct{}{}:
			default:
			}
		}()
		if fail {
			_, _ = io.Copy(io.Discard, r.Body)
			if h.failStatus == http.StatusPreconditionFailed {
				h.mu.Lock()
				h.revision++
				h.mu.Unlock()
			}
			http.Error(w, "retry this update", h.failStatus)
			return
		}
		dest := t.TempDir()
		files, err := publish.ExtractDeltaWithLimit(r.Body, dest, publish.MaxExpandedBytes)
		if err != nil {
			t.Error(err)
			http.Error(w, "bad delta", 400)
			return
		}
		if h.onPost != nil {
			h.onPost(post)
		}
		if post == 1 && h.block != nil {
			select {
			case <-h.block:
			case <-r.Context().Done():
				return
			}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if r.Header.Get("If-Match") != strconv.Quote(fmt.Sprintf("rev-%d", h.revision)) {
			http.Error(w, "stale revision", http.StatusPreconditionFailed)
			return
		}
		if err := publish.CompleteDelta(h.dir, dest, files, publish.MaxExpandedBytes); err != nil {
			t.Error(err)
			http.Error(w, "invalid merged site", 400)
			return
		}
		h.dir, h.files = dest, files
		h.site.WS = r.URL.Query().Get("ws") == "true"
		h.revision++
		h.commits++
		_ = json.NewEncoder(w).Encode(h.site)
	}))
	t.Cleanup(server.Close)
	opts := pubUploadOptions{Folder: root, Endpoint: server.URL + "/_expose/v1/sites", Server: server.URL, Key: "token", Name: "docs", SourceID: strings.Repeat("a", 64)}
	return h, server.Client(), opts, pubUploadResult{Site: h.site, Files: h.files, Diff: diff, Uploaded: true}, snapshot
}

func fastPubWatchTiming() pubWatchTiming {
	return pubWatchTiming{Poll: 5 * time.Millisecond, Debounce: 15 * time.Millisecond, Stats: 10 * time.Millisecond, Retry: 10 * time.Millisecond}
}

func TestPubWatchCumulativeChanges(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "home")
	h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
	h.failCount, h.failStatus = 1, http.StatusServiceUnavailable
	opts.WS = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output pubWatchTestOutput
	phase := 0
	output.onText = func(text string) {
		if !strings.Contains(text, "\nWatch") || !strings.Contains(text, "Files") {
			return
		}
		var counts string
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "Watch") {
				counts = line
			}
		}
		want := []string{
			"New 1 (4.0 B) | Updated 0 (0.0 B) | Deleted 0 (0.0 B)",
			"New 2 (7.0 B) | Updated 0 (0.0 B) | Deleted 0 (0.0 B)",
			"New 2 (7.0 B) | Updated 1 (14.0 B) | Deleted 0 (0.0 B)",
			"New 2 (7.0 B) | Updated 1 (14.0 B) | Deleted 1 (14.0 B)",
		}
		if phase >= len(want) || !strings.Contains(counts, want[phase]) {
			return
		}
		switch phase {
		case 0:
			writeIncrementalCLIFile(t, root, "new.txt", "new")
		case 1:
			writeIncrementalCLIFile(t, root, "new.txt", "edited content")
		case 2:
			if err := os.Remove(filepath.Join(root, "new.txt")); err != nil {
				t.Fatal(err)
			}
		case 3:
			cancel()
		}
		phase++
	}
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, true, false, fastPubWatchTiming()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if phase != 4 || h.commits != 3 || h.posts != 4 {
		t.Fatalf("cumulative changes failed: phase=%d commits=%d posts=%d\n%s", phase, h.commits, h.posts, output.String())
	}
	if !h.site.WS {
		t.Fatal("watch updates lost the WS option")
	}
}

func TestPubWatchIgnoresNewEmptyFiles(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "home")
	writeIncrementalCLIFile(t, root, "existing.txt", "old")
	h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	phase := 0
	var createdAt time.Time
	var output pubWatchTestOutput
	output.onEvent = func(event pubWatchEvent) {
		if event.Type == "stats" {
			switch phase {
			case 0:
				writeIncrementalCLIFile(t, root, "new.txt", "")
				createdAt, phase = time.Now(), 1
			case 1:
				if time.Since(createdAt) < 100*time.Millisecond {
					return
				}
				h.mu.Lock()
				posts, fetches := h.posts, h.fetches
				h.mu.Unlock()
				if posts != 0 || fetches != 0 {
					t.Fatalf("empty placeholder triggered comparison/upload: posts=%d fetches=%d", posts, fetches)
				}
				writeIncrementalCLIFile(t, root, "existing.txt", "")
				phase = 2
			}
			return
		}
		if event.Type != "published" || phase < 2 {
			return
		}
		h.mu.Lock()
		paths := pubPublishedPaths(h.files)
		h.mu.Unlock()
		switch phase {
		case 2:
			if event.Changes.New.Files != 0 || event.Changes.Updated != (pubWatchFileStats{1, 0}) || paths["new.txt"] {
				t.Fatalf("existing truncation published the empty placeholder: %+v", event.Changes)
			}
			writeIncrementalCLIFile(t, root, "new.txt", "content")
			phase = 3
		case 3:
			if event.Changes.New != (pubWatchFileStats{1, 7}) || event.Changes.Updated.Files != 0 || !paths["new.txt"] {
				t.Fatalf("first content save was not counted only as new: %+v", event.Changes)
			}
			if err := os.Remove(filepath.Join(root, "existing.txt")); err != nil {
				t.Fatal(err)
			}
			phase = 4
		case 4:
			if event.Changes.Deleted != (pubWatchFileStats{1, 0}) || paths["existing.txt"] {
				t.Fatalf("published empty file deletion was missed: %+v", event.Changes)
			}
			phase = 5
			cancel()
		}
	}
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if phase != 5 || h.commits != 3 {
		t.Fatalf("empty-file watch flow incomplete: phase=%d commits=%d", phase, h.commits)
	}
}

func TestPubUploadNewEmptyFilesOnlyIgnoredForWatch(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(fmt.Sprintf("watch=%v", watch), func(t *testing.T) {
			root := t.TempDir()
			writeIncrementalCLIFile(t, root, "index.html", "home")
			writeIncrementalCLIFile(t, root, "existing.txt", "")
			h, client, opts, _, _ := newPubWatchTestServer(t, root)
			writeIncrementalCLIFile(t, root, "new.txt", "")
			opts.IgnoreNewEmpty = watch
			opts.ExpectedSiteID = h.site.ID
			result, err := uploadPublishedSite(context.Background(), client, opts)
			if err != nil {
				t.Fatal(err)
			}
			paths := pubPublishedPaths(result.Files)
			if !paths["existing.txt"] || paths["new.txt"] == watch {
				t.Fatalf("incorrect empty-file policy: %+v", result.Files)
			}
			if result.Diff.Updated != 0 || result.Diff.Deleted != 0 || (result.Diff.Added == 0) != watch {
				t.Fatalf("incorrect empty-file counts: %+v", result.Diff)
			}
			snapshot, err := publish.FileSnapshot(root)
			if err != nil {
				t.Fatal(err)
			}
			filterPubWatchSnapshot(snapshot, paths)
			if snapshot["existing.txt"] == nil || (snapshot["new.txt"] == nil) != watch {
				t.Fatalf("watch snapshot did not follow published paths: %+v", snapshot)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if pubPublishedPaths(h.files)["new.txt"] == watch {
				t.Fatalf("archive did not follow empty-file policy: %+v", h.files)
			}
		})
	}
}

func TestPubWatchPublishesChangedFilesAndStreamsStats(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{"index.html": "old", "keep.txt": "keep", "deleted.txt": "gone"} {
		writeIncrementalCLIFile(t, root, name, content)
	}
	h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats, published := 0, 0
	var output pubWatchTestOutput
	output.onEvent = func(event pubWatchEvent) {
		switch event.Type {
		case "stats":
			stats++
			if stats == 1 {
				writeIncrementalCLIFile(t, root, "index.html", "new content")
				writeIncrementalCLIFile(t, root, "assets/new.txt", "123")
				writeIncrementalCLIFile(t, root, ".env", "private")
				if err := os.Remove(filepath.Join(root, "deleted.txt")); err != nil {
					t.Fatal(err)
				}
			}
		case "published":
			published++
			if published == 2 {
				changes := event.Changes
				if changes == nil || changes.New != (pubWatchFileStats{1, 3}) || changes.Updated != (pubWatchFileStats{1, 11}) || changes.Deleted != (pubWatchFileStats{1, 4}) || changes.Unchanged != (pubWatchFileStats{1, 4}) {
					t.Errorf("wrong watch change stats: %+v", changes)
				}
				cancel()
			}
		}
	}
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if published != 2 || stats == 0 || h.posts != 1 || h.commits != 1 {
		t.Fatalf("watch did not publish and poll: publications=%d stats=%d posts=%d commits=%d", published, stats, h.posts, h.commits)
	}
	for name, want := range map[string]string{"index.html": "new content", "assets/new.txt": "123", "keep.txt": "keep"} {
		data, err := os.ReadFile(filepath.Join(h.dir, name))
		if err != nil || string(data) != want {
			t.Fatalf("remote %s: %q, %v", name, data, err)
		}
	}
	for _, name := range []string{"deleted.txt", ".env"} {
		if _, err := os.Stat(filepath.Join(h.dir, name)); !os.IsNotExist(err) {
			t.Fatalf("unexpected remote %s: %v", name, err)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("watch output is not NDJSON: %s", line)
		}
	}
}

func TestPubWatchKeepsStatsAndQueuesSavesDuringUpload(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "v1")
	h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
	release := make(chan struct{})
	h.block = release
	h.onPost = func(post int) {
		if post == 1 {
			if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("v3"), 0600); err != nil {
				t.Error(err)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stats, published, statsWhileUploading := 0, 0, 0
	released := false
	var output pubWatchTestOutput
	output.onEvent = func(event pubWatchEvent) {
		if event.Type == "stats" {
			stats++
			if stats == 1 {
				writeIncrementalCLIFile(t, root, "index.html", "v2")
			}
			h.mu.Lock()
			active := h.active
			h.mu.Unlock()
			if active > 0 && !released {
				statsWhileUploading++
				if statsWhileUploading == 3 {
					close(release)
					released = true
				}
			}
		}
		if event.Type == "published" {
			published++
			if published == 3 {
				cancel()
			}
		}
	}
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if published != 3 || h.posts != 2 || h.maxActive != 1 || statsWhileUploading < 3 {
		t.Fatalf("in-flight save lost or stats blocked: published=%d posts=%d maxActive=%d statsDuringUpload=%d", published, h.posts, h.maxActive, statsWhileUploading)
	}
	data, err := os.ReadFile(filepath.Join(h.dir, "index.html"))
	if err != nil || string(data) != "v3" {
		t.Fatalf("latest save was not published: %q, %v", data, err)
	}
}

func TestPubWatchSkipsIgnoredAndContentIdenticalChanges(t *testing.T) {
	for _, touchPublic := range []bool{false, true} {
		t.Run(fmt.Sprintf("touch-public=%v", touchPublic), func(t *testing.T) {
			root := t.TempDir()
			writeIncrementalCLIFile(t, root, "index.html", "home")
			h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stats := 0
			var output pubWatchTestOutput
			output.onEvent = func(event pubWatchEvent) {
				if event.Type != "stats" {
					return
				}
				stats++
				if stats == 1 {
					writeIncrementalCLIFile(t, root, ".claude/private.txt", "ignored")
					if touchPublic {
						future := time.Now().Add(time.Second)
						if err := os.Chtimes(filepath.Join(root, "index.html"), future, future); err != nil {
							t.Fatal(err)
						}
					}
				}
				if stats == 15 {
					cancel()
				}
			}
			if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
				t.Fatal(err)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.posts != 0 || stats != 15 || !touchPublic && h.fetches != 0 || touchPublic && h.fetches == 0 {
				t.Fatalf("unnecessary uploads or missing comparison: posts=%d fetches=%d stats=%d", h.posts, h.fetches, stats)
			}
		})
	}
}

func TestPubWatchRetriesFailedUpdates(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusPreconditionFailed} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			root := t.TempDir()
			writeIncrementalCLIFile(t, root, "index.html", "old")
			h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
			h.failCount, h.failStatus = 1, status
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			changed, reported, published := false, false, 0
			var output pubWatchTestOutput
			output.onEvent = func(event pubWatchEvent) {
				if event.Type == "stats" && !changed {
					changed = true
					writeIncrementalCLIFile(t, root, "index.html", "new")
				}
				if event.Type == "error" && strings.Contains(event.Message, strconv.Itoa(status)) {
					reported = true
				}
				if event.Type == "published" {
					published++
					if published == 2 {
						cancel()
					}
				}
			}
			if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
				t.Fatal(err)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if !reported || h.posts != 2 || h.commits != 1 || h.fetches != 2 || published != 2 {
				t.Fatalf("failed update was not retried safely: reported=%v posts=%d commits=%d fetches=%d published=%d", reported, h.posts, h.commits, h.fetches, published)
			}
		})
	}
}

func TestPubWatchRecoversFromIncompleteBuild(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "old")
	h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	removed, recovered, published := false, false, 0
	var output pubWatchTestOutput
	output.onEvent = func(event pubWatchEvent) {
		if event.Type == "stats" && !removed {
			removed = true
			if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
				t.Fatal(err)
			}
		}
		if event.Type == "error" && strings.Contains(event.Message, "root index.html") {
			recovered = true
			writeIncrementalCLIFile(t, root, "index.html", "new")
		}
		if event.Type == "published" {
			published++
			if published == 2 {
				cancel()
			}
		}
	}
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !recovered || h.posts != 1 || published != 2 {
		t.Fatalf("incomplete build stopped watching: recovered=%v posts=%d published=%d", recovered, h.posts, published)
	}
}

func TestPubWatchStopsOnMissingSiteOrDeniedStats(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			root := t.TempDir()
			writeIncrementalCLIFile(t, root, "index.html", "home")
			h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
			h.statsStatus = status
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output bytes.Buffer
			err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming())
			var httpErr pubStatsHTTPError
			h.mu.Lock()
			defer h.mu.Unlock()
			if !errors.As(err, &httpErr) || httpErr.status != status || h.posts != 0 {
				t.Fatalf("watch did not stop safely: posts=%d error=%v", h.posts, err)
			}
		})
	}
}

func TestPubWatchSnapshotDetectsAtomicAndTimestampPreservingSaves(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "old")
	before, err := publish.FileSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	writeIncrementalCLIFile(t, root, ".env", "private")
	same, err := publish.FileSnapshot(root)
	if err != nil || !samePubSnapshot(before, same) {
		t.Fatalf("ignored files changed the snapshot: %v", err)
	}
	writeIncrementalCLIFile(t, root, "replacement.html", "new")
	if err := os.Chtimes(filepath.Join(root, "replacement.html"), before["index.html"].ModTime(), before["index.html"].ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "replacement.html"), filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	after, err := publish.FileSnapshot(root)
	if err != nil || samePubSnapshot(before, after) {
		t.Fatalf("same-size, same-mtime atomic save was missed: %v", err)
	}
	if pubFileChangeTime(after["index.html"]) != nil {
		writeIncrementalCLIFile(t, root, "index.html", "old")
		if err := os.Chtimes(filepath.Join(root, "index.html"), after["index.html"].ModTime(), after["index.html"].ModTime()); err != nil {
			t.Fatal(err)
		}
		preserved, err := publish.FileSnapshot(root)
		if err != nil || samePubSnapshot(after, preserved) {
			t.Fatalf("timestamp-preserving write was missed: %v", err)
		}
	}
}

func TestPubWatchDashboardAndCursorCleanup(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	now := time.Now()
	display := pubStatsDisplay{out: &output, interactive: true, watch: &pubWatchStatus{
		Folder: "./dist\x1b[2J", State: "Watching for changes", LastPublished: now,
		Diff: publish.FileDiff{Added: 1, AddedBytes: 1024, Updated: 2, UpdatedBytes: 2048, Deleted: 3, DeletedBytes: 4096},
	}}
	stats := domain.PublishedSiteStats{Site: domain.PublishedSite{ID: "site_watch", Hostname: "docs.example.com"}, CapturedAt: now, ResponseBytes: 1024, FileCount: 275, FileBytes: 111 << 20}
	if err := display.render(stats, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	stats.CapturedAt = now.Add(time.Second)
	stats.ResponseBytes += 2048
	if err := display.render(stats, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := display.render(stats, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	display.close()
	for _, want := range []string{"275 files, 111.0 MiB", "New 1 (1.0 KiB)", "Updated 2 (2.0 KiB)", "Deleted 3 (4.0 KiB)", "2.0 KiB/s", "Ctrl+C stops watching", termui.ShowCur} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("watch dashboard missing %q: %s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "Local folder") || strings.Contains(output.String(), "Last publish") || strings.Contains(output.String(), "Unchanged") {
		t.Fatalf("watch dashboard contains removed rows: %s", output.String())
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "Watch") && (!strings.Contains(line, "New 1") || !strings.Contains(line, "Updated 2") || !strings.Contains(line, "Deleted 3")) {
			t.Fatalf("watch counts are not combined: %s", line)
		}
		if strings.HasPrefix(line, "Files") && strings.Contains(line, "New") {
			t.Fatalf("watch counts remain in Files: %s", line)
		}
	}
	if strings.Contains(output.String(), "\x1b[2J") {
		t.Fatal("local folder injected terminal controls")
	}
}

func TestPubWatchDashboardStyles(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var output bytes.Buffer
	display := pubStatsDisplay{out: &output, interactive: true, watch: &pubWatchStatus{
		Diff: publish.FileDiff{Added: 1, AddedBytes: 1024, Updated: 2, UpdatedBytes: 2048, Deleted: 3, DeletedBytes: 4096},
	}}
	if err := display.render(domain.PublishedSiteStats{}, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	style := termui.Styler{Color: true}
	want := style.Style("", fmt.Sprintf("%-19s", "Watch")) +
		style.Style(termui.Dim, "New ") + style.Style("", "1") + style.Style(termui.Dim, " (1.0 KiB)") +
		style.Style(termui.Dim, " | ") +
		style.Style(termui.Dim, "Updated ") + style.Style("", "2") + style.Style(termui.Dim, " (2.0 KiB)") +
		style.Style(termui.Dim, " | ") +
		style.Style(termui.Dim, "Deleted ") + style.Style("", "3") + style.Style(termui.Dim, " (4.0 KiB)") + "\n"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("watch row has incorrect styling: got %q, want %q", output.String(), want)
	}
}

func TestPubWatchDashboardOmitsStatus(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	watch := pubWatchStatus{}
	display := pubStatsDisplay{out: &output, interactive: true, watch: &watch}
	for i, state := range []string{"Publishing local changes", "Archiving: 50%", "Uploading: 50%", "Watching for changes"} {
		output.Reset()
		watch.State = state
		watch.Diff.Updated = i
		if err := display.render(domain.PublishedSiteStats{}, time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "\nStatus") || strings.Contains(output.String(), state) {
			t.Fatalf("dashboard shows watch status: %s", output.String())
		}
		want := fmt.Sprintf("Updated %d (0.0 B)", i)
		if !strings.Contains(output.String(), want) {
			t.Fatalf("dashboard did not update change counts: %s", output.String())
		}
	}
}

func TestPubWatchFlagValidation(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, args := range [][]string{{"list", "--watch"}, {"delete", "--domain=docs", "--watch"}, {"connect", "--domain=docs", "--watch"}} {
		if err := pubCommand(context.Background(), args); err == nil || !strings.Contains(err.Error(), "watch is only supported when uploading") {
			t.Fatalf("accepted watch flag for %v: %v", args, err)
		}
	}
	if err := pubCommand(context.Background(), []string{".", "--watch", "--full"}); err == nil || !strings.Contains(err.Error(), "cannot be combined with --full") {
		t.Fatalf("accepted a full-upload watch: %v", err)
	}
}

func TestPubWatchDebouncesEditorSaves(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "old")
	h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	postedAt := make(chan time.Time, 1)
	h.onPost = func(int) { postedAt <- time.Now() }
	var savedAt time.Time
	published, changed := 0, false
	var output pubWatchTestOutput
	output.onEvent = func(event pubWatchEvent) {
		if event.Type == "stats" && !changed {
			changed = true
			for _, content := range []string{"first", "second", "latest"} {
				writeIncrementalCLIFile(t, root, "index.html", content)
			}
			savedAt = time.Now()
		}
		if event.Type == "published" {
			published++
			if published == 2 {
				cancel()
			}
		}
	}
	timing := fastPubWatchTiming()
	timing.Debounce = 80 * time.Millisecond
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, timing); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.posts != 1 || published != 2 {
		t.Fatalf("editor saves were not batched: posts=%d published=%d", h.posts, published)
	}
	if elapsed := (<-postedAt).Sub(savedAt); elapsed < timing.Debounce {
		t.Fatalf("published before saves settled: %s", elapsed)
	}
	data, err := os.ReadFile(filepath.Join(h.dir, "index.html"))
	if err != nil || string(data) != "latest" {
		t.Fatalf("did not publish the final save: %q, %v", data, err)
	}
}

func TestPubWatchCancelsInFlightUpload(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "old")
	h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
	h.block = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	changed := false
	var output pubWatchTestOutput
	output.onEvent = func(event pubWatchEvent) {
		if event.Type != "stats" {
			return
		}
		if !changed {
			changed = true
			writeIncrementalCLIFile(t, root, "index.html", "new")
		}
		h.mu.Lock()
		active := h.active
		h.mu.Unlock()
		if active > 0 {
			cancel()
		}
	}
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.finished:
	case <-time.After(time.Second):
		t.Fatal("cancelled upload did not stop")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.commits != 0 || h.active != 0 {
		t.Fatalf("cancelled upload committed or leaked: commits=%d active=%d", h.commits, h.active)
	}
}

func TestPubWatchCLIInitialUploadAndJSON(t *testing.T) {
	for _, staged := range []bool{false, true} {
		t.Run(fmt.Sprintf("staged=%v", staged), func(t *testing.T) {
			testPubWatchCLIInitialUploadAndJSON(t, staged)
		})
	}
}

func testPubWatchCLIInitialUploadAndJSON(t *testing.T, staged bool) {
	t.Chdir(t.TempDir())
	stdout, stderr := captureIncrementalOutput(t)
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "home")
	if staged {
		pubTestGit(t, root, "init", "-q")
		pubTestGit(t, root, "add", "index.html")
		writeIncrementalCLIFile(t, root, "index.html", "unstaged")
		writeIncrementalCLIFile(t, root, "untracked.txt", "ignored")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var mu sync.Mutex
	posts, stats := 0, 0
	site := domain.PublishedSite{ID: "site_watch", Hostname: "docs.example.com"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/_expose/v1/sites/files":
			w.Header().Set("ETag", `"new"`)
			_, _ = io.WriteString(w, "[]")
		case r.Method == http.MethodPost && r.URL.Path == "/_expose/v1/sites":
			posts++
			dest := t.TempDir()
			files, err := publish.ExtractDeltaWithLimit(r.Body, dest, publish.MaxExpandedBytes)
			if err != nil {
				t.Error(err)
				http.Error(w, "bad initial delta", 400)
				return
			}
			if err := publish.CompleteDelta("", dest, files, publish.MaxExpandedBytes); err != nil {
				t.Error(err)
			}
			if data, err := os.ReadFile(filepath.Join(dest, "index.html")); err != nil || string(data) != "home" {
				t.Errorf("initial watch upload included unstaged content: %q, %v", data, err)
			}
			if len(files) != 1 {
				t.Errorf("initial watch upload included untracked files: %+v", files)
			}
			_ = json.NewEncoder(w).Encode(site)
		case r.Method == http.MethodGet && r.URL.Path == "/_expose/v1/sites/site_watch/stats":
			stats++
			if stats == 2 {
				cancel()
				return
			}
			_ = json.NewEncoder(w).Encode(domain.PublishedSiteStats{Site: site})
		default:
			t.Errorf("unexpected watch CLI request: %s %s", r.Method, r.URL)
			http.Error(w, "bad request", 400)
		}
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	args := []string{root, "--watch", "--json", "--server", server.URL, "--api-key", "token"}
	if staged {
		args = append(args, "--staged")
	}
	if err := pubCommand(ctx, args); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 || stats != 2 {
		t.Fatalf("watch CLI did not upload then connect: posts=%d stats=%d", posts, stats)
	}
	data, err := os.ReadFile(stdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("missing JSON watch events: %s", data)
	}
	for _, line := range lines {
		var event pubWatchEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil || (event.Type != "published" && event.Type != "stats") {
			t.Fatalf("invalid watch event: %s, %v", line, err)
		}
	}
	data, err = os.ReadFile(stderr.Name())
	if err != nil || len(data) != 0 {
		t.Fatalf("JSON watch printed progress: %s, %v", data, err)
	}
}

func TestPubWatchHumanOutputAndProgress(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("interactive=%v", interactive), func(t *testing.T) {
			root := t.TempDir()
			writeIncrementalCLIFile(t, root, "index.html", "old")
			h, client, opts, initial, snapshot := newPubWatchTestServer(t, root)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			changed, committed := false, false
			var output pubWatchTestOutput
			output.onText = func(text string) {
				if !changed && strings.Contains(text, "\nWatch") && strings.Contains(text, "Files") {
					changed = true
					writeIncrementalCLIFile(t, root, "index.html", "new")
				}
				if strings.Contains(text, "Published local changes.") {
					committed = true
					cancel()
				}
			}
			if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, interactive, false, fastPubWatchTiming()); err != nil {
				t.Fatal(err)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if !committed || h.posts != 1 {
				t.Fatalf("human watch did not publish: committed=%v posts=%d", committed, h.posts)
			}
			wants := []string{"docs.example.com", "Watch", "Updated", "Published local changes."}
			if !interactive {
				wants = append(wants, "Archiving", "Uploading")
			}
			for _, want := range wants {
				if !strings.Contains(output.String(), want) {
					t.Errorf("watch output missing %q: %s", want, output.String())
				}
			}
			if interactive && !strings.Contains(output.String(), termui.ShowCur) {
				t.Fatal("watch did not restore the cursor")
			}
			if !interactive && strings.Contains(output.String(), "\x1b") {
				t.Fatal("redirected watch output contains ANSI escapes")
			}
		})
	}
}
