package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

func TestPubDeleteCLI(t *testing.T) {
	t.Chdir(t.TempDir())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("Authorization") != "Bearer owner" {
			t.Errorf("unexpected unpublish request: %s, auth %q", r.Method, r.Header.Get("Authorization"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/v1/sites/docs" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	for _, prefix := range [][]string{
		{"pub", "delete"}, {"client", "pub", "delete"},
	} {
		t.Run(strings.Join(prefix, " "), func(t *testing.T) {
			args := append(append([]string{}, prefix...), "--domain=docs", "--server", server.URL, "--api-key", "owner", "--json")
			if code := Run(args); code != 0 {
				t.Fatalf("unpublish exit code: %d", code)
			}
		})
	}
	if code := runPub(context.Background(), []string{"delete", "--domain=missing", "--server", server.URL, "--api-key", "owner"}); code == 0 {
		t.Fatal("missing site reported success")
	}
	if err := pubCommand(context.Background(), []string{"delete"}); err == nil || !strings.Contains(err.Error(), "expose pub list") {
		t.Fatalf("missing subdomain should explain how to find sites: %v", err)
	}
	if err := pubCommand(context.Background(), []string{"delete", "docs"}); err == nil || !strings.Contains(err.Error(), "invalid publish folder") {
		t.Fatalf("positional subdomain should be treated as a folder: %v", err)
	}
	if err := pubCommand(context.Background(), []string{"delete", "./dist", "--domain=docs"}); err == nil {
		t.Fatal("accepted two deletion selectors")
	}
}

func TestPubCLIUploadsValidatedArchive(t *testing.T) {
	t.Chdir(t.TempDir())
	root := filepath.Join(t.TempDir(), "dist")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("SPA"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "launch.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	warnings, err := os.CreateTemp(t.TempDir(), "warnings")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = warnings.Close() }()
	originalStderr := os.Stderr
	os.Stderr = warnings
	defer func() { os.Stderr = originalStderr }()
	dest := t.TempDir()
	calls := 0
	sourceID := ""
	deleted := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("missing API key")
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]domain.PublishedSite{{ID: "site_test", Hostname: "docs.example.com", SourceID: sourceID}})
			return
		}
		if r.Method == http.MethodDelete {
			if r.URL.Path != "/v1/sites/site_test" {
				t.Errorf("wrong folder publication deleted: %s", r.URL.Path)
			}
			deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/sites" || r.URL.Query().Get("domain") != "docs" || r.URL.Query().Get("ttl") != "24h0m0s" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if err := os.RemoveAll(dest); err != nil {
			t.Error(err)
		}
		if err := publish.Extract(r.Body, dest); err != nil {
			t.Error(err)
			http.Error(w, "bad archive", 400)
			return
		}
		sourceID = r.URL.Query().Get("source_id")
		if len(sourceID) != 64 {
			t.Errorf("missing folder identifier: %q", sourceID)
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"id":"site_test","hostname":"docs.example.com","created_at":"2026-01-01T00:00:00Z"}`)
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	args := []string{root, "--server", server.URL, "--api-key", "token", "--domain", "docs", "--ttl", "24h", "--json"}
	if err := pubCommand(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("got %d requests", calls)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=value"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pubCommand(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("filtered folder did not reach server")
	}
	for _, name := range []string{".env", ".claude"} {
		if _, err := os.Stat(filepath.Join(dest, name)); !os.IsNotExist(err) {
			t.Fatalf("ignored path %s reached server: %v", name, err)
		}
	}
	text, err := os.ReadFile(warnings.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", ".claude"} {
		if !strings.Contains(string(text), "Warning: ignored \""+name+"\"") {
			t.Errorf("missing warning for %s: %s", name, text)
		}
	}
	if err := pubCommand(context.Background(), []string{"delete", root, "--server", server.URL, "--api-key", "token"}); err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("folder publication was not deleted")
	}
}

func TestFolderDeletionRejectsMissingOrAmbiguousPublications(t *testing.T) {
	for _, sites := range [][]domain.PublishedSite{
		{{ID: "other", SourceID: "different-folder"}},
		{{ID: "one", SourceID: "folder"}, {ID: "two", SourceID: "folder"}},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Error("ambiguous selection must not delete anything")
			}
			_ = json.NewEncoder(w).Encode(sites)
		}))
		_, err := publishedFolderSite(context.Background(), server.Client(), server.URL, "key", "folder")
		server.Close()
		if err == nil || !strings.Contains(err.Error(), "--domain") {
			t.Fatalf("expected an error directing user to --domain, got %v", err)
		}
	}
}
