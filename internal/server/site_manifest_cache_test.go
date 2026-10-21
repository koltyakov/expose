package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func TestPublishedManifestCachesImmutableRevision(t *testing.T) {
	srv := &Server{cfg: config.ServerConfig{PublishDir: t.TempDir()}}
	site := domain.PublishedSite{ID: "site", ContentID: "first"}
	root := filepath.Join(srv.publishDir(), site.StorageID())
	writeIncrementalTestFile(t, root, "index.html", "old")
	data, err := srv.publishedManifest(site)
	if err != nil {
		t.Fatal(err)
	}
	// Files are immutable in production. Remove one here to prove cache hits
	// do not reopen or rehash content, including concurrent requests.
	if err := os.Remove(filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			next, err := srv.publishedManifest(site)
			if err != nil || !bytes.Equal(data, next) {
				t.Errorf("cache miss: %s %v", next, err)
			}
		})
	}
	wg.Wait()
	site.ContentID = "second"
	if _, err := srv.publishedManifest(site); err == nil {
		t.Fatal("missing revision was accepted")
	}
	writeIncrementalTestFile(t, filepath.Join(srv.publishDir(), site.StorageID()), "index.html", "new content")
	next, err := srv.publishedManifest(site)
	if err != nil || bytes.Equal(data, next) {
		t.Fatalf("revision or failed load was cached incorrectly: %s %v", next, err)
	}
}

func TestSiteManifestCacheBoundsAndEviction(t *testing.T) {
	var cache siteManifestCache
	for i := range siteManifestCacheEntries + 1 {
		cache.put(fmt.Sprint(i), []byte("[]\n"))
	}
	if len(cache.entries) != siteManifestCacheEntries {
		t.Fatal("entry bound exceeded")
	}
	cache.put("large", make([]byte, siteManifestCacheBytes))
	if len(cache.entries) != 1 || cache.bytes != siteManifestCacheBytes {
		t.Fatal("byte bound not enforced")
	}
	cache.put("oversized", make([]byte, siteManifestCacheBytes+1))
	if _, ok := cache.get("oversized"); ok {
		t.Fatal("oversized manifest retained")
	}
	cache.put("spare-capacity", make([]byte, 1, siteManifestCacheBytes+1))
	if _, ok := cache.get("spare-capacity"); ok {
		t.Fatal("cache ignored retained spare capacity")
	}
	data, _ := cache.get("large")
	cache.delete("large")
	if cache.bytes != 0 || len(cache.entries) != 0 || len(data) != siteManifestCacheBytes {
		t.Fatal("eviction corrupted accounting or a borrowed response")
	}
}

func TestPublishedManifestEvictedOnReplaceAndDelete(t *testing.T) {
	srv, store := newIncrementalTestServer(t)
	root := t.TempDir()
	for _, content := range []string{"first", "replacement"} {
		writeIncrementalTestFile(t, root, "index.html", content)
		var archive bytes.Buffer
		if err := publish.Archive(root, &archive); err != nil {
			t.Fatal(err)
		}
		w := incrementalSiteRequest(srv, "POST", serviceapi.Sites+"?domain=docs", "owner", "", archive.Bytes())
		if w.Code != 201 && w.Code != 200 {
			t.Fatalf("publish: %d %s", w.Code, w.Body.String())
		}
		if len(srv.siteManifests.entries) != 0 {
			t.Fatal("replacement retained the old manifest")
		}
		w = incrementalSiteRequest(srv, "GET", serviceapi.Sites+"/files?domain=docs", "owner", "", nil)
		var files []domain.PublishedFile
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &files) != nil || len(files) != 1 || files[0].Size != int64(len(content)) {
			t.Fatalf("manifest: %d %s", w.Code, w.Body.String())
		}
		site, err := store.FindPublishedSite(t.Context(), "docs.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := srv.siteManifests.get(site.StorageID()); !ok {
			t.Fatal("manifest was not cached")
		}
	}
	w := incrementalSiteRequest(srv, "DELETE", serviceapi.Sites+"/docs", "owner", "", nil)
	if w.Code != 204 || len(srv.siteManifests.entries) != 0 || srv.siteManifests.bytes != 0 {
		t.Fatal("deletion retained manifest data")
	}
}

func BenchmarkPublishedManifest(b *testing.B) {
	srv := &Server{cfg: config.ServerConfig{PublishDir: b.TempDir()}}
	site := domain.PublishedSite{ID: "site"}
	dir := filepath.Join(srv.publishDir(), site.StorageID())
	if err := os.Mkdir(dir, 0700); err != nil {
		b.Fatal(err)
	}
	for i := range 100 {
		name := fmt.Sprintf("asset-%d.js", i)
		if i == 0 {
			name = "index.html"
		}
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, 4096), 0600); err != nil {
			b.Fatal(err)
		}
	}
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprintf("cached=%t", cached), func(b *testing.B) {
			if _, err := srv.publishedManifest(site); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if !cached {
					srv.siteManifests.delete(site.StorageID())
				}
				if _, err := srv.publishedManifest(site); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
