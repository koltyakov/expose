package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/publish"
)

func pubTestGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is not installed")
	}
	flags := []string{"-C", root, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + filepath.Join(root, ".git", "no-hooks")}
	cmd := exec.Command("git", append(flags, args...)...)
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, data)
	}
	return strings.TrimSpace(string(data))
}

func newPubStagedTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	pubTestGit(t, root, "init", "-q")
	writeIncrementalCLIFile(t, root, "index.html", "home")
	writeIncrementalCLIFile(t, root, "existing.txt", "old")
	pubTestGit(t, root, "add", ".")
	pubTestGit(t, root, "commit", "-qm", "initial")
	return root
}

func readPubStagedFile(t *testing.T, source *pubStagedWatch, name, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(source.folder, name))
	if err != nil || string(data) != want {
		t.Fatalf("staged %s = %q, %v; want %q", name, data, err, want)
	}
}

func TestPubStagedWatchContentsAndScope(t *testing.T) {
	root := newPubStagedTestRepo(t)
	writeIncrementalCLIFile(t, root, "site/index.html", "staged")
	writeIncrementalCLIFile(t, root, "site/assets/line\nbreak.txt", "asset")
	writeIncrementalCLIFile(t, root, "site/.env", "secret")
	pubTestGit(t, root, "add", ".")
	writeIncrementalCLIFile(t, root, "site/index.html", "unstaged")
	writeIncrementalCLIFile(t, root, "site/untracked.txt", "untracked")
	source, err := newPubStagedWatch(context.Background(), filepath.Join(root, "site"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	readPubStagedFile(t, source, "index.html", "staged")
	readPubStagedFile(t, source, "assets/line\nbreak.txt", "asset")
	for _, name := range []string{".env", "untracked.txt", "existing.txt"} {
		if _, err := os.Stat(filepath.Join(source.folder, name)); !os.IsNotExist(err) {
			t.Fatalf("excluded file %s was materialized: %v", name, err)
		}
	}
	before := source.folder
	writeIncrementalCLIFile(t, root, "existing.txt", "outside")
	pubTestGit(t, root, "add", "existing.txt")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source.folder != before {
		t.Fatal("out-of-folder staging triggered a source change")
	}
	pubTestGit(t, root, "add", "site/index.html")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	readPubStagedFile(t, source, "index.html", "unstaged")
}

func TestPubStagedWatchUnstagingUpdatesAndCommitsDoNotPublish(t *testing.T) {
	root := newPubStagedTestRepo(t)
	source, err := newPubStagedWatch(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	writeIncrementalCLIFile(t, root, "existing.txt", "staged")
	pubTestGit(t, root, "add", "existing.txt")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	readPubStagedFile(t, source, "existing.txt", "staged")
	before := source.folder
	pubTestGit(t, root, "reset", "-q", "HEAD", "--", "existing.txt")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source.folder == before {
		t.Fatal("unstaging did not update the staged source")
	}
	readPubStagedFile(t, source, "existing.txt", "old")
	pubTestGit(t, root, "add", "existing.txt")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	readPubStagedFile(t, source, "existing.txt", "staged")
	before = source.folder
	pubTestGit(t, root, "commit", "-qm", "staged update")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source.folder != before {
		t.Fatal("committing changed the staged source")
	}
}

func TestPubStagedWatchUnstagesAdditionsAndDeletions(t *testing.T) {
	root := newPubStagedTestRepo(t)
	source, err := newPubStagedWatch(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	writeIncrementalCLIFile(t, root, "new.txt", "staged new")
	pubTestGit(t, root, "add", "new.txt")
	pubTestGit(t, root, "rm", "--cached", "existing.txt")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	readPubStagedFile(t, source, "new.txt", "staged new")
	if _, err := os.Stat(filepath.Join(source.folder, "existing.txt")); !os.IsNotExist(err) {
		t.Fatalf("staged deletion did not remove existing.txt: %v", err)
	}
	writeIncrementalCLIFile(t, root, "existing.txt", "unstaged edit")
	writeIncrementalCLIFile(t, root, "new.txt", "unstaged new")
	pubTestGit(t, root, "reset", "-q", "HEAD", "--", "new.txt", "existing.txt")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	readPubStagedFile(t, source, "existing.txt", "old")
	if _, err := os.Stat(filepath.Join(source.folder, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("unstaging an addition did not remove new.txt: %v", err)
	}
}

func TestPubStagedWatchValidation(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, args := range [][]string{{".", "--staged"}, {"list", "--staged"}, {"connect", "--domain=docs", "--staged"}, {"delete", "--domain=docs", "--staged"}} {
		if err := pubCommand(context.Background(), args); err == nil || !strings.Contains(err.Error(), "requires --watch") {
			t.Fatalf("accepted invalid staged flags %v: %v", args, err)
		}
	}
	if source, err := newPubStagedWatch(context.Background(), t.TempDir()); err == nil {
		source.close()
		t.Fatal("staged watch accepted a non-Git folder")
	}
	root := t.TempDir()
	pubTestGit(t, root, "init", "-q")
	writeIncrementalCLIFile(t, root, "index.html", "untracked")
	if source, err := newPubStagedWatch(context.Background(), root); err == nil || !strings.Contains(err.Error(), "index.html") {
		if source != nil {
			source.close()
		}
		t.Fatalf("accepted an unstaged root index: %v", err)
	}
	pubTestGit(t, root, "add", "index.html")
	source, err := newPubStagedWatch(context.Background(), root)
	if err != nil {
		t.Fatalf("staged watch should support an unborn branch: %v", err)
	}
	defer source.close()
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPubStagedWatchQueuesStagingDuringUpload(t *testing.T) {
	root := newPubStagedTestRepo(t)
	source, err := newPubStagedWatch(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	before := source.folder
	writeIncrementalCLIFile(t, root, "existing.txt", "queued staged")
	pubTestGit(t, root, "add", "existing.txt")
	if err := source.observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if source.folder != before {
		t.Fatal("observing staging mutated an in-flight upload source")
	}
	pubTestGit(t, root, "commit", "-qm", "queued change")
	writeIncrementalCLIFile(t, root, "existing.txt", "newer unstaged")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	readPubStagedFile(t, source, "existing.txt", "queued staged")
}

func TestPubStagedWatchRecoversFromRootDeletion(t *testing.T) {
	root := newPubStagedTestRepo(t)
	source, err := newPubStagedWatch(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	before := source.folder
	pubTestGit(t, root, "rm", "--cached", "index.html")
	if err := source.sync(context.Background()); err == nil || !strings.Contains(err.Error(), "index.html") {
		t.Fatalf("accepted staged root deletion: %v", err)
	}
	pubTestGit(t, root, "reset", "-q", "HEAD", "--", "index.html")
	if err := source.sync(context.Background()); err != nil {
		t.Fatalf("watch did not resume after root deletion was undone: %v", err)
	}
	if source.folder != before {
		t.Fatal("invalid root deletion changed the staged source")
	}
}

func TestPubStagedWatchPublishesIndexOnStagingAndUnstaging(t *testing.T) {
	root := newPubStagedTestRepo(t)
	h, client, opts, initial, _ := newPubWatchTestServer(t, root)
	source, err := newPubStagedWatch(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	opts.Staged = source
	snapshot, err := opts.watchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	phase := 0
	var editedAt time.Time
	var output pubWatchTestOutput
	output.onEvent = func(event pubWatchEvent) {
		if event.Type == "stats" {
			switch phase {
			case 0:
				writeIncrementalCLIFile(t, root, "index.html", "staged index")
				writeIncrementalCLIFile(t, root, "new.txt", "staged new")
				if err := os.Remove(filepath.Join(root, "existing.txt")); err != nil {
					t.Fatal(err)
				}
				editedAt, phase = time.Now(), 1
			case 1:
				if time.Since(editedAt) < 150*time.Millisecond {
					return
				}
				h.mu.Lock()
				posts, fetches := h.posts, h.fetches
				h.mu.Unlock()
				if posts != 0 || fetches != 0 {
					t.Fatalf("unstaged changes triggered a publish: posts=%d fetches=%d", posts, fetches)
				}
				pubTestGit(t, root, "add", "-A")
				writeIncrementalCLIFile(t, root, "index.html", "later unstaged index")
				writeIncrementalCLIFile(t, root, "new.txt", "later unstaged new")
				writeIncrementalCLIFile(t, root, "untracked.txt", "ignored")
				phase = 2
			}
			return
		}
		if event.Type != "published" || (phase != 2 && phase != 3) {
			return
		}
		if changes := event.Changes; changes.New.Files != 1 || changes.Updated.Files != 1 || changes.Deleted.Files != 1 {
			t.Fatalf("incorrect staged changes: %+v", changes)
		}
		h.mu.Lock()
		remote := h.dir
		h.mu.Unlock()
		contents := map[string]string{"index.html": "staged index", "new.txt": "staged new"}
		absent := []string{"existing.txt", "untracked.txt"}
		if phase == 3 {
			contents = map[string]string{"index.html": "home", "existing.txt": "old"}
			absent = []string{"new.txt", "untracked.txt"}
		}
		for name, want := range contents {
			data, err := os.ReadFile(filepath.Join(remote, name))
			if err != nil || string(data) != want {
				t.Fatalf("published %s = %q, %v; want staged %q", name, data, err, want)
			}
		}
		for _, name := range absent {
			if _, err := os.Stat(filepath.Join(remote, name)); !os.IsNotExist(err) {
				t.Fatalf("excluded/deleted file %s was published: %v", name, err)
			}
		}
		if phase == 2 {
			// Leave working-tree edits intact; only the index should be synced.
			pubTestGit(t, root, "reset", "-q", "HEAD", "--", "index.html", "existing.txt", "new.txt")
			phase = 3
			return
		}
		phase = 4
		cancel()
	}
	if err := watchPublishedSite(ctx, client, opts, initial, snapshot, &output, false, true, fastPubWatchTiming()); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if phase != 4 || h.commits != 2 {
		t.Fatalf("staged watch flow incomplete: phase=%d commits=%d", phase, h.commits)
	}
}

func TestPubStagedWatchRenames(t *testing.T) {
	root := newPubStagedTestRepo(t)
	source, err := newPubStagedWatch(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer source.close()
	pubTestGit(t, root, "mv", "existing.txt", "renamed file.txt")
	if err := source.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	files, err := publish.Manifest(source.folder)
	if err != nil {
		t.Fatal(err)
	}
	if paths := pubPublishedPaths(files); paths["existing.txt"] || !paths["renamed file.txt"] {
		t.Fatalf("staged rename not applied: %+v", files)
	}
	readPubStagedFile(t, source, "renamed file.txt", "old")
}

func TestPubStagedWatchRejectsLinks(t *testing.T) {
	root := newPubStagedTestRepo(t)
	if err := os.Symlink("index.html", filepath.Join(root, "link.html")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	pubTestGit(t, root, "add", "link.html")
	if source, err := newPubStagedWatch(context.Background(), root); err == nil || !strings.Contains(err.Error(), "regular staged files") {
		if source != nil {
			source.close()
		}
		t.Fatalf("accepted staged symlink: %v", err)
	}
}
