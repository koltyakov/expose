package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

type pubWatchTiming struct {
	Poll, Debounce, Stats, Retry time.Duration
}

func (t pubWatchTiming) defaults() pubWatchTiming {
	if t.Poll <= 0 {
		t.Poll = 250 * time.Millisecond
	}
	if t.Debounce <= 0 {
		t.Debounce = 200 * time.Millisecond
	}
	if t.Stats <= 0 {
		t.Stats = time.Second
	}
	if t.Retry <= 0 {
		t.Retry = time.Second
	}
	return t
}

type pubWatchStatus struct {
	Folder, State, StatsError string
	LastPublished             time.Time
	Diff                      publish.FileDiff
}

type pubWatchFileStats struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

type pubWatchChanges struct {
	New       pubWatchFileStats `json:"new"`
	Updated   pubWatchFileStats `json:"updated"`
	Deleted   pubWatchFileStats `json:"deleted"`
	Unchanged pubWatchFileStats `json:"unchanged"`
}

type pubWatchEvent struct {
	Type    string                     `json:"type"`
	Time    time.Time                  `json:"time"`
	Site    *domain.PublishedSite      `json:"site,omitempty"`
	Stats   *domain.PublishedSiteStats `json:"stats,omitempty"`
	Changes *pubWatchChanges           `json:"changes,omitempty"`
	Message string                     `json:"message,omitempty"`
}

type pubWatchUpdate struct {
	kind      string
	message   string
	result    pubUploadResult
	snapshot  map[string]os.FileInfo
	stats     domain.PublishedSiteStats
	roundTrip time.Duration
	err       error
}

func samePubSnapshot(a, b map[string]os.FileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for name, current := range a {
		previous, exists := b[name]
		if !exists || current.Size() != previous.Size() || !current.ModTime().Equal(previous.ModTime()) || current.Mode() != previous.Mode() || !os.SameFile(current, previous) || !reflect.DeepEqual(pubFileChangeTime(current), pubFileChangeTime(previous)) {
			return false
		}
	}
	return true
}

// Unix change times catch writes that preserve size and modification time.
// FileInfo.Sys is platform-specific; other platforms use the portable fields.
func pubFileChangeTime(info os.FileInfo) any {
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer && !value.IsNil() {
		value = value.Elem()
	}
	if value.Kind() == reflect.Struct {
		for _, name := range []string{"Ctim", "Ctimespec", "Ctime"} {
			field := value.FieldByName(name)
			if field.IsValid() && field.CanInterface() {
				return field.Interface()
			}
		}
	}
	return nil
}

// watchPublishedSite owns all terminal output. HTTP workers report through a
// channel so stats continue refreshing while an upload is in progress.
func watchPublishedSite(parent context.Context, client *http.Client, opts pubUploadOptions, initial pubUploadResult, baseline map[string]os.FileInfo, out io.Writer, interactive, jsonOutput bool, timing pubWatchTiming) error {
	timing = timing.defaults()
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	status := pubWatchStatus{Folder: opts.Folder, State: "Watching for changes", LastPublished: time.Now(), Diff: initial.Diff}
	display := pubStatsDisplay{out: out, interactive: interactive && !jsonOutput, watch: &status}
	defer display.close()
	encoder := json.NewEncoder(out)
	emit := func(event pubWatchEvent) error {
		event.Time = time.Now().UTC()
		return encoder.Encode(event)
	}
	emitPublished := func(result pubUploadResult) error {
		diff := result.Diff
		return emit(pubWatchEvent{Type: "published", Site: &result.Site, Changes: &pubWatchChanges{
			New: pubWatchFileStats{diff.Added, diff.AddedBytes}, Updated: pubWatchFileStats{diff.Updated, diff.UpdatedBytes},
			Deleted: pubWatchFileStats{diff.Deleted, diff.DeletedBytes}, Unchanged: pubWatchFileStats{diff.Unchanged, diff.UnchangedBytes},
		}})
	}
	if jsonOutput {
		if err := emitPublished(initial); err != nil {
			return err
		}
	} else {
		if err := writePublishedSiteResult(out, initial.Site, interactive && os.Getenv("NO_COLOR") == ""); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "Watching %s for local changes. Ctrl+C stops watching; the site stays hosted.\n", config.SanitizeTerminalString(opts.Folder)); err != nil {
			return err
		}
	}
	opts.Full, opts.SkipUnchanged, opts.ExpectedSiteID, opts.Progress = false, true, initial.Site.ID, nil
	events := make(chan pubWatchUpdate, 16)
	send := func(event pubWatchUpdate) {
		select {
		case events <- event:
		case <-ctx.Done():
		}
	}
	statsClient := *client
	statsClient.Timeout = 10 * time.Second
	statsBusy, uploadBusy := false, false
	startStats := func() {
		statsBusy = true
		workers.Add(1)
		go func() {
			defer workers.Done()
			started := time.Now()
			stats, err := fetchPublishedStats(ctx, &statsClient, opts.Endpoint+"/"+url.PathEscape(initial.Site.ID)+"/stats", opts.Key)
			if err == nil && stats.Site.ID != initial.Site.ID {
				err = pubStatsHTTPError{status: http.StatusNotFound}
			}
			send(pubWatchUpdate{kind: "stats", stats: stats, roundTrip: time.Since(started), err: err})
		}()
	}
	startUpload := func(snapshot map[string]os.FileInfo) {
		uploadBusy = true
		status.State = "Publishing local changes"
		uploadOpts := opts
		if !jsonOutput {
			uploadOpts.Progress = &pubProgress{out: io.Discard, interactive: true, notify: func(text string) {
				// Progress can be dropped; completion events must be delivered.
				select {
				case events <- pubWatchUpdate{kind: "progress", message: text}:
				default:
				}
			}}
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			result, err := uploadPublishedSite(ctx, client, uploadOpts)
			send(pubWatchUpdate{kind: "publish", result: result, snapshot: snapshot, err: err})
		}()
	}
	var lastStats *domain.PublishedSiteStats
	var lastRoundTrip time.Duration
	redraw := func() error {
		if !jsonOutput && interactive && lastStats != nil {
			return display.render(*lastStats, lastRoundTrip)
		}
		return nil
	}
	reportError := func(err error) error {
		text := config.SanitizeTerminalString(err.Error())
		if jsonOutput {
			return emit(pubWatchEvent{Type: "error", Message: text})
		}
		if !interactive || lastStats == nil {
			_, err = fmt.Fprintln(out, "Watch:", text)
			return err
		}
		return redraw()
	}
	poll := time.NewTicker(timing.Poll)
	defer poll.Stop()
	statsPoll := time.NewTicker(timing.Stats)
	defer statsPoll.Stop()
	observed := baseline
	var changedAt, nextRetry time.Time
	retryDelay := timing.Retry
	scanError, uploadError := "", ""
	startStats()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-statsPoll.C:
			if !statsBusy {
				startStats()
			}
		case <-poll.C:
			snapshot, err := publish.FileSnapshot(opts.Folder)
			if err != nil {
				if !uploadBusy {
					status.State = "Waiting for valid local files: " + err.Error()
				}
				if scanError != err.Error() {
					scanError = err.Error()
					if err := reportError(err); err != nil {
						return err
					}
				}
				continue
			}
			if scanError != "" {
				scanError = ""
				if !uploadBusy {
					status.State = "Watching for changes"
					if err := redraw(); err != nil {
						return err
					}
				}
			}
			if !samePubSnapshot(snapshot, observed) {
				observed, changedAt = snapshot, time.Now()
				nextRetry, retryDelay = time.Time{}, timing.Retry
			}
			if !uploadBusy && !samePubSnapshot(snapshot, baseline) && time.Since(changedAt) >= timing.Debounce && !time.Now().Before(nextRetry) {
				startUpload(snapshot)
				if err := redraw(); err != nil {
					return err
				}
			}
		case event := <-events:
			if ctx.Err() != nil {
				return nil
			}
			switch event.kind {
			case "progress":
				text, _, _ := strings.Cut(event.message, "\n")
				if text != pubChangeHeading {
					status.State = text
				}
				if !interactive && !strings.HasPrefix(text, "Archiving:") && !strings.HasPrefix(text, "Uploading:") {
					if _, err := fmt.Fprintln(out, event.message); err != nil {
						return err
					}
				}
				if err := redraw(); err != nil {
					return err
				}
			case "publish":
				uploadBusy = false
				if event.err != nil {
					var httpErr pubHTTPError
					terminal := errors.As(event.err, &httpErr) && (httpErr.status == 401 || httpErr.status == 403 || httpErr.status == 404 || httpErr.status == 410)
					status.State = "Publish failed; retrying: " + event.err.Error()
					if terminal {
						status.State = "Watch stopped: " + event.err.Error()
					}
					if event.err.Error() != uploadError {
						uploadError = event.err.Error()
						if err := reportError(event.err); err != nil {
							return err
						}
					}
					if terminal {
						return event.err
					}
					nextRetry = time.Now().Add(retryDelay)
					retryDelay = min(retryDelay*2, 10*time.Second)
					continue
				}
				// Use the pre-upload snapshot. A save during the upload must trigger
				// another comparison, not be mistaken for already-published content.
				baseline = event.snapshot
				uploadError, nextRetry, retryDelay = "", time.Time{}, timing.Retry
				status.State = "Watching for changes"
				if event.result.Uploaded {
					status.LastPublished = time.Now()
					// Count committed changes for the whole watch session. Comparisons
					// and failed uploads must not replace or inflate these totals.
					status.Diff.Added += event.result.Diff.Added
					status.Diff.AddedBytes += event.result.Diff.AddedBytes
					status.Diff.Updated += event.result.Diff.Updated
					status.Diff.UpdatedBytes += event.result.Diff.UpdatedBytes
					status.Diff.Deleted += event.result.Diff.Deleted
					status.Diff.DeletedBytes += event.result.Diff.DeletedBytes
					if jsonOutput {
						if err := emitPublished(event.result); err != nil {
							return err
						}
					} else if _, err := fmt.Fprintln(out, "Published local changes."); err != nil {
						return err
					}
				}
				if err := redraw(); err != nil {
					return err
				}
			case "stats":
				statsBusy = false
				if event.err != nil {
					var httpErr pubStatsHTTPError
					if errors.As(event.err, &httpErr) && httpErr.status < 500 && httpErr.status != http.StatusTooManyRequests {
						status.StatsError = event.err.Error()
						if err := reportError(event.err); err != nil {
							return err
						}
						return event.err
					}
					status.StatsError = "Stats connection interrupted; reconnecting"
					if err := reportError(event.err); err != nil {
						return err
					}
					continue
				}
				status.StatsError = ""
				lastStats, lastRoundTrip = &event.stats, event.roundTrip
				if jsonOutput {
					if err := emit(pubWatchEvent{Type: "stats", Stats: lastStats}); err != nil {
						return err
					}
				} else if err := display.render(*lastStats, lastRoundTrip); err != nil {
					return err
				}
			}
		}
	}
}
