package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

func captureIncrementalOutput(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	stdout, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	t.Cleanup(func() {
		os.Stdout, os.Stderr = originalStdout, originalStderr
		_ = stdout.Close()
		_ = stderr.Close()
	})
	return stdout, stderr
}

func writeIncrementalCLIFile(t *testing.T, root, name, content string) {
	t.Helper()
	file := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPubIncrementalCLI(t *testing.T) {
	for _, tc := range []struct {
		name, summary   string
		byDomain, json  bool
		initial, modify bool
		deleteOnly      bool
		changedFiles    int
	}{
		{"changed files", "Changes (incremental):\n  New            1 file   5.0 B\n  Updated        1 file   3.0 B\n  Deleted        1 file   8.0 B\n  Unchanged      1 file   9.0 B", true, false, false, true, false, 2},
		{"first publication", "", false, true, true, false, false, 3},
		{"no changes", "Changes (incremental):\n  New            0 files  0.0 B\n  Updated        0 files  0.0 B\n  Deleted        0 files  0.0 B\n  Unchanged      3 files  20.0 B", false, false, false, false, false, 0},
		{"no changes JSON", "", true, true, false, false, false, 0},
		{"deletions only", "Changes (incremental):\n  New            0 files  0.0 B\n  Updated        0 files  0.0 B\n  Deleted        1 file   8.0 B\n  Unchanged      2 files  12.0 B", true, false, false, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			stdout, stderr := captureIncrementalOutput(t)
			base, root := t.TempDir(), t.TempDir()
			for _, dir := range []string{base, root} {
				writeIncrementalCLIFile(t, dir, "index.html", "old")
				writeIncrementalCLIFile(t, dir, "assets/keep.js", "unchanged")
				writeIncrementalCLIFile(t, dir, "deleted.txt", "obsolete")
			}
			if tc.modify {
				writeIncrementalCLIFile(t, root, "index.html", "new")
				writeIncrementalCLIFile(t, root, "new.txt", "added")
			}
			if tc.modify || tc.deleteOnly {
				if err := os.Remove(filepath.Join(root, "deleted.txt")); err != nil {
					t.Fatal(err)
				}
			}
			writeIncrementalCLIFile(t, root, ".env", "secret")
			local, err := publish.Manifest(root)
			if err != nil {
				t.Fatal(err)
			}
			remote, err := publish.Manifest(base)
			if err != nil {
				t.Fatal(err)
			}
			revision := `"snapshot"`
			if tc.initial {
				remote, revision = []domain.PublishedFile{}, `"new"`
			}
			diff, err := publish.DiffFiles(local, remote)
			if err != nil {
				t.Fatal(err)
			}
			if len(diff.Changed) != tc.changedFiles {
				t.Fatalf("bad test diff: %+v", diff)
			}
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Header.Get("Authorization") != "Bearer token" || len(r.URL.Query().Get("source_id")) != 64 {
					t.Error("missing credentials or folder selector")
				}
				if tc.byDomain != (r.URL.Query().Get("domain") == "docs") {
					t.Errorf("wrong domain selector: %s", r.URL)
				}
				if r.Method == http.MethodGet && r.URL.Path == "/_expose/v1/sites/files" {
					w.Header().Set("ETag", revision)
					_ = json.NewEncoder(w).Encode(remote)
					return
				}
				if r.Method != http.MethodPost || r.URL.Path != "/_expose/v1/sites" || r.URL.Query().Get("incremental") != "true" || r.Header.Get("If-Match") != revision {
					t.Errorf("unexpected incremental upload: %s %s, revision %q", r.Method, r.URL, r.Header.Get("If-Match"))
				}
				if r.ContentLength <= 0 || r.Header.Get("Content-Type") != "application/gzip" {
					t.Error("missing delta archive metadata")
				}
				dest := t.TempDir()
				files, err := publish.ExtractDeltaWithLimit(r.Body, dest, publish.MaxExpandedBytes)
				if err != nil {
					t.Error(err)
					http.Error(w, "invalid delta", 400)
					return
				}
				changed, err := publish.Manifest(root) // Manifest validates the complete local site.
				if err != nil || !reflect.DeepEqual(files, changed) {
					t.Errorf("delta manifest does not match local files: %+v, %v", files, err)
				}
				changedPaths := make(map[string]bool)
				for _, file := range diff.Changed {
					changedPaths[file.Path] = true
				}
				for _, file := range files {
					_, err := os.Stat(filepath.Join(dest, file.Path))
					if changedPaths[file.Path] && err != nil || !changedPaths[file.Path] && !os.IsNotExist(err) {
						t.Errorf("wrong file contents transferred for %s: %v", file.Path, err)
					}
				}
				baseDir := base
				if tc.initial {
					baseDir = ""
				}
				if err := publish.CompleteDelta(baseDir, dest, files, publish.MaxExpandedBytes); err != nil {
					t.Error(err)
					http.Error(w, "invalid merged site", 400)
					return
				}
				merged, err := publish.Manifest(dest)
				if err != nil || !reflect.DeepEqual(merged, local) {
					t.Errorf("wrong merged contents: %+v, %v", merged, err)
				}
				_ = json.NewEncoder(w).Encode(domain.PublishedSite{ID: "site_test", Hostname: "docs.example.com"})
			}))
			defer server.Close()
			original := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = original }()
			args := []string{root, "--server", server.URL, "--api-key", "token"}
			if tc.byDomain {
				args = append(args, "--domain=docs")
			}
			if tc.json {
				args = append(args, "--json")
			}
			if err := pubCommand(context.Background(), args); err != nil {
				t.Fatal(err)
			}
			if requests != 2 {
				t.Fatalf("expected file listing and delta upload, got %d requests", requests)
			}
			text, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			if tc.json {
				if len(text) != 0 {
					t.Fatalf("JSON publishing printed progress: %s", text)
				}
				data, err := os.ReadFile(stdout.Name())
				if err != nil || !json.Valid(data) {
					t.Fatalf("invalid JSON result: %s, %v", data, err)
				}
			} else if !strings.Contains(string(text), tc.summary) || !strings.Contains(string(text), "Uploaded ") {
				t.Fatalf("missing incremental progress: %s", text)
			}
			data, err := os.ReadFile(stdout.Name())
			if err != nil {
				t.Fatal(err)
			}
			if tc.json {
				var site domain.PublishedSite
				if err := json.Unmarshal(data, &site); err != nil || site.ID != "site_test" {
					t.Fatalf("missing published metadata: %s, %v", data, err)
				}
			} else if !strings.Contains(string(data), "Published docs") {
				t.Fatalf("missing Published footer: %s", data)
			}
		})
	}
}

func TestPubIncrementalRejectsInvalidRemoteManifest(t *testing.T) {
	t.Chdir(t.TempDir())
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "home")
	files, err := publish.Manifest(root)
	if err != nil {
		t.Fatal(err)
	}
	badFile := files[0]
	badFile.Path = "../outside"
	for _, tc := range []struct {
		name, revision, body, want string
		status                     int
	}{
		{"old server", "", "not found", "use --full", 404},
		{"access denied", "", "forbidden", "403", 403},
		{"missing revision", "", "[]", "publication revision", 200},
		{"weak revision", `W/"snapshot"`, "[]", "publication revision", 200},
		{"bad JSON", `"snapshot"`, "broken", "invalid published file manifest", 200},
		{"unsafe path", `"snapshot"`, mustIncrementalJSON(t, []domain.PublishedFile{badFile}), "unsafe publish path", 200},
		{"duplicate", `"snapshot"`, mustIncrementalJSON(t, append(files, files...)), "duplicate manifest path", 200},
		{"oversized", `"snapshot"`, strings.Repeat(" ", publish.MaxManifestBytes+1), "manifest exceeds", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posts := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
				}
				w.Header().Set("ETag", tc.revision)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			original := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = original }()
			err := pubCommand(context.Background(), []string{root, "--json", "--server", server.URL, "--api-key", "token"})
			if err == nil || !strings.Contains(err.Error(), tc.want) || posts != 0 {
				t.Fatalf("invalid manifest reached upload: posts=%d, error=%v", posts, err)
			}
		})
	}
}

func mustIncrementalJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPubChangeSummary(t *testing.T) {
	diff := publish.FileDiff{
		Added: 2, AddedBytes: 2048,
		Updated: 1, UpdatedBytes: 1 << 20,
		Unchanged: 270, UnchangedBytes: 111 << 20,
	}
	want := "Changes (incremental):\n" +
		"  New            2 files  2.0 KiB\n" +
		"  Updated        1 file   1.0 MiB\n" +
		"  Deleted        0 files  0.0 B\n" +
		"  Unchanged    270 files  111.0 MiB"
	if got := pubChangeSummary(diff); got != want {
		t.Fatalf("change summary:\n%s\nwant:\n%s", got, want)
	}
}

func TestFullFlagOnlyAppliesToUploads(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, args := range [][]string{{"list", "--full"}, {"delete", "--domain=docs", "--full"}, {"connect", "--domain=docs", "--full"}} {
		if err := pubCommand(context.Background(), args); err == nil || !strings.Contains(err.Error(), "full is only supported when uploading") {
			t.Fatalf("accepted full flag for %v: %v", args, err)
		}
	}
}

func TestPubFullSkipsFileComparison(t *testing.T) {
	t.Chdir(t.TempDir())
	stdout, stderr := captureIncrementalOutput(t)
	root := t.TempDir()
	contents := map[string]string{
		"index.html":    "home",
		"assets/app.js": "unchanged asset",
	}
	for name, content := range contents {
		writeIncrementalCLIFile(t, root, name, content)
	}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodPost || r.URL.Path != "/_expose/v1/sites" {
			t.Errorf("full upload fetched a file list: %s %s", r.Method, r.URL)
			http.Error(w, "file listing unsupported", http.StatusNotFound)
			return
		}
		if r.URL.Query().Has("incremental") || r.Header.Get("If-Match") != "" {
			t.Error("full upload used incremental metadata")
		}
		dest := t.TempDir()
		if err := publish.Extract(r.Body, dest); err != nil {
			t.Error(err)
			http.Error(w, "invalid full archive", http.StatusBadRequest)
			return
		}
		for name, want := range contents {
			data, err := os.ReadFile(filepath.Join(dest, name))
			if err != nil || string(data) != want {
				t.Errorf("full upload omitted %s: %q, %v", name, data, err)
			}
		}
		_ = json.NewEncoder(w).Encode(domain.PublishedSite{ID: "site_test", Hostname: "docs.example.com"})
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	if err := pubCommand(context.Background(), []string{root, "--full", "--json", "--server", server.URL, "--api-key", "token"}); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("full upload made %d requests, want one POST", requests)
	}
	data, err := os.ReadFile(stdout.Name())
	if err != nil || !json.Valid(data) {
		t.Fatalf("invalid full-upload JSON: %s, %v", data, err)
	}
	data, err = os.ReadFile(stderr.Name())
	if err != nil || len(data) != 0 {
		t.Fatalf("full JSON upload printed progress: %s, %v", data, err)
	}
}
