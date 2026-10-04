package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func newIncrementalTestServer(t *testing.T) (*Server, *sqlite.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sites.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, token := range []string{"owner", "other"} {
		if _, err := st.CreateAPIKey(context.Background(), token, auth.HashAPIKey(token, "")); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.authLimiter, srv.regLimiter = nil, nil
	return srv, st
}

func incrementalSiteRequest(srv *Server, method, path, token, revision string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	if revision != "" {
		r.Header.Set("If-Match", revision)
	}
	w := httptest.NewRecorder()
	srv.handleSites(w, r)
	return w
}

func writeIncrementalTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	file := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementalPublishedSiteLifecycle(t *testing.T) {
	for _, byDomain := range []bool{false, true} {
		name := "folder"
		if byDomain {
			name = "domain"
		}
		t.Run(name, func(t *testing.T) {
			srv, st := newIncrementalTestServer(t)
			root := t.TempDir()
			writeIncrementalTestFile(t, root, "index.html", "old")
			writeIncrementalTestFile(t, root, "assets/keep.js", strings.Repeat("unchanged", 10000))
			writeIncrementalTestFile(t, root, "removed.txt", "obsolete")
			sourceID := strings.Repeat("a", 64)
			query := "source_id=" + sourceID
			if byDomain {
				query += "&domain=docs"
			}
			var full bytes.Buffer
			if err := publish.Archive(root, &full); err != nil {
				t.Fatal(err)
			}
			w := incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query+"&ttl=1h", "owner", "", full.Bytes())
			if w.Code != http.StatusCreated {
				t.Fatalf("initial full upload: %d %s", w.Code, w.Body.String())
			}
			var first domain.PublishedSite
			if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
				t.Fatal(err)
			}
			before, err := st.FindPublishedSite(context.Background(), first.Hostname)
			if err != nil {
				t.Fatal(err)
			}
			visit := httptest.NewRequest("GET", "https://"+first.Hostname+"/", nil)
			visit.RemoteAddr = "192.0.2.1:1234"
			srv.handlePublic(httptest.NewRecorder(), visit)
			assertTotals := func(count int, size int64) {
				t.Helper()
				w := incrementalSiteRequest(srv, "GET", "/_expose/v1/sites/"+first.ID+"/stats", "owner", "", nil)
				var stats domain.PublishedSiteStats
				if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &stats) != nil || stats.FileCount != count || stats.FileBytes != size || stats.Visitors != 1 {
					t.Fatalf("wrong published file totals: %d %s", w.Code, w.Body.String())
				}
			}
			assertTotals(3, 90011)
			fetch := func(token string) ([]domain.PublishedFile, string) {
				t.Helper()
				w := incrementalSiteRequest(srv, "GET", "/_expose/v1/sites/files?"+query, token, "", nil)
				if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("manifest response: %d %s", w.Code, w.Body.String())
				}
				var files []domain.PublishedFile
				if err := json.Unmarshal(w.Body.Bytes(), &files); err != nil {
					t.Fatal(err)
				}
				return files, w.Header().Get("ETag")
			}
			remote, revision := fetch("owner")
			want, err := publish.Manifest(root)
			if err != nil || !reflect.DeepEqual(remote, want) || revision != publishedSiteRevision(&before) {
				t.Fatalf("wrong file snapshot: %+v, %s, %v", remote, revision, err)
			}
			otherFiles, otherRevision := fetch("other")
			if len(otherFiles) != 0 || otherRevision != `"new"` {
				t.Fatal("file listing disclosed another owner's publication")
			}
			w = incrementalSiteRequest(srv, "GET", "/_expose/v1/sites/files?"+query, "invalid", "", nil)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated manifest: %d", w.Code)
			}
			writeIncrementalTestFile(t, root, "index.html", "new")
			writeIncrementalTestFile(t, root, "new.txt", "added")
			if err := os.Remove(filepath.Join(root, "removed.txt")); err != nil {
				t.Fatal(err)
			}
			local, err := publish.Manifest(root)
			if err != nil {
				t.Fatal(err)
			}
			var delta bytes.Buffer
			if err := publish.ArchiveDelta(root, &delta, local, remote, nil); err != nil {
				t.Fatal(err)
			}
			w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query+"&incremental=true&ttl=48h", "owner", revision, delta.Bytes())
			if w.Code != http.StatusOK {
				t.Fatalf("incremental replacement: %d %s", w.Code, w.Body.String())
			}
			after, err := st.FindPublishedSite(context.Background(), before.Hostname)
			if err != nil {
				t.Fatal(err)
			}
			if after.ID != before.ID || after.SourceID != before.SourceID || !after.CreatedAt.Equal(before.CreatedAt) || after.StorageID() == before.StorageID() || !after.ExpiresAt.After(*before.ExpiresAt) {
				t.Fatalf("replacement lost identity, snapshot, or TTL: %+v", after)
			}
			got, newRevision := fetch("owner")
			assertTotals(3, 90008)
			if !reflect.DeepEqual(got, local) || newRevision == revision {
				t.Fatalf("wrong incremental contents: %+v, %s", got, newRevision)
			}
			w = httptest.NewRecorder()
			srv.handlePublic(w, httptest.NewRequest("GET", "https://"+after.Hostname+"/", nil))
			if w.Code != http.StatusOK || w.Body.String() != "new" {
				t.Fatalf("incremental site not live: %d %s", w.Code, w.Body.String())
			}
			if _, err := os.Stat(filepath.Join(srv.publishDir(), after.StorageID(), "removed.txt")); !os.IsNotExist(err) {
				t.Fatalf("removed file survived: %v", err)
			}
			// A second publisher working against the same base cannot overwrite it.
			w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query+"&incremental=true", "owner", revision, delta.Bytes())
			if w.Code != http.StatusPreconditionFailed {
				t.Fatalf("stale revision accepted: %d %s", w.Code, w.Body.String())
			}
			// Deletion-only and no-content-change uploads send no file contents.
			if err := os.Remove(filepath.Join(root, "new.txt")); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				remote, revision = fetch("owner")
				local, err = publish.Manifest(root)
				if err != nil {
					t.Fatal(err)
				}
				delta.Reset()
				var progress publish.ArchiveProgress
				if err := publish.ArchiveDelta(root, &delta, local, remote, func(p publish.ArchiveProgress) { progress = p }); err != nil {
					t.Fatal(err)
				}
				if progress.Files != 0 || progress.Bytes != 0 {
					t.Fatalf("unchanged contents were uploaded: %+v", progress)
				}
				w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query+"&incremental=true", "owner", revision, delta.Bytes())
				if w.Code != http.StatusOK {
					t.Fatalf("metadata-only upload: %d %s", w.Code, w.Body.String())
				}
			}
			// The publication survives a server restart with the committed directory.
			srv = New(srv.cfg, st, srv.log, "test")
			if err := srv.cleanupPublishedSites(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, _ = fetch("owner")
			assertTotals(2, 90003)
			if !reflect.DeepEqual(got, local) {
				t.Fatalf("restarted server lost incremental content: %+v", got)
			}
		})
	}
}

func TestIncrementalPublicationGuards(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	root := t.TempDir()
	writeIncrementalTestFile(t, root, "index.html", "home")
	writeIncrementalTestFile(t, root, "assets/keep.js", "unchanged")
	files, err := publish.Manifest(root)
	if err != nil {
		t.Fatal(err)
	}
	var initial, unchanged bytes.Buffer
	if err := publish.ArchiveDelta(root, &initial, files, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := publish.ArchiveDelta(root, &unchanged, files, files, nil); err != nil {
		t.Fatal(err)
	}
	query := "domain=docs&incremental=true"
	w := incrementalSiteRequest(srv, "GET", "/_expose/v1/sites/files?domain=docs", "owner", "", nil)
	if w.Code != http.StatusOK || w.Body.String() != "[]\n" || w.Header().Get("ETag") != `"new"` {
		t.Fatalf("first publication manifest: %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		name, query, revision string
		body                  []byte
		status                int
	}{
		{"missing revision", query, "", initial.Bytes(), http.StatusPreconditionRequired},
		{"missing selector", "incremental=true", `"new"`, initial.Bytes(), http.StatusBadRequest},
		{"bad boolean", "domain=docs&incremental=invalid", `"new"`, initial.Bytes(), http.StatusBadRequest},
		{"missing initial contents", query, `"new"`, unchanged.Bytes(), http.StatusBadRequest},
		{"bad archive", query, `"new"`, []byte("broken"), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+tc.query, "owner", tc.revision, tc.body)
			if w.Code != tc.status {
				t.Fatalf("guard: %d %s, want %d", w.Code, w.Body.String(), tc.status)
			}
		})
	}
	w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query, "owner", `"new"`, initial.Bytes())
	if w.Code != http.StatusCreated {
		t.Fatalf("first incremental upload: %d %s", w.Code, w.Body.String())
	}
	site, err := st.FindPublishedSite(context.Background(), "docs.example.com")
	if err != nil {
		t.Fatal(err)
	}
	revision := publishedSiteRevision(&site)
	// Watch updates cannot recreate or overwrite another publication at the
	// same hostname, even if the client has its current content revision.
	w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query+"&site_id=site_deleted", "owner", revision, unchanged.Bytes())
	if w.Code != http.StatusNotFound {
		t.Fatalf("watch ignored publication identity: %d %s", w.Code, w.Body.String())
	}
	// "new" cannot be used to overwrite a site created after the file listing.
	w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query, "owner", `"new"`, initial.Bytes())
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("concurrent first publication accepted: %d %s", w.Code, w.Body.String())
	}
	w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query, "other", `"new"`, initial.Bytes())
	if w.Code != http.StatusConflict {
		t.Fatalf("other owner overwrote publication: %d %s", w.Code, w.Body.String())
	}
	srv.cfg.PublishMaxBytes = 10 // Unchanged 9-byte asset plus 4-byte index exceeds it.
	w = incrementalSiteRequest(srv, "POST", "/_expose/v1/sites?"+query, "owner", revision, unchanged.Bytes())
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("final site limit ignored unchanged content: %d %s", w.Code, w.Body.String())
	}
	stored, err := st.FindPublishedSite(context.Background(), "docs.example.com")
	if err != nil || stored.StorageID() != site.StorageID() {
		t.Fatalf("failed upload changed live snapshot: %+v, %v", stored, err)
	}
	entries, err := os.ReadDir(srv.publishDir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed uploads left staging files: %v, %v", entries, err)
	}
	for _, path := range []string{"/_expose/v1/sites/files?source_id=invalid", "/_expose/v1/sites/files?domain=bad_domain", "/_expose/v1/sites/files?domain="} {
		w = incrementalSiteRequest(srv, "GET", path, "owner", "", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid manifest selector %s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
