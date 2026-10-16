package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/serviceapi"
)

// A client that stops reading must not pin the global publication lock. Once
// cleanup queues for that lock, RWMutex also blocks every subsequent reader.
func TestStalledSiteResponseDoesNotBlockPublications(t *testing.T) {
	for _, path := range []string{"/", "/client/route", "/missing.js", "/.env"} {
		t.Run(path, func(t *testing.T) {
			srv, _ := newIncrementalTestServer(t)
			root := t.TempDir()
			original := strings.Repeat("original content\n", 10000)
			writeIncrementalTestFile(t, root, "index.html", original)
			var archive bytes.Buffer
			if err := publish.Archive(root, &archive); err != nil {
				t.Fatal(err)
			}
			w := incrementalSiteRequest(srv, "POST", serviceapi.Sites+"?domain=docs", "owner", "", archive.Bytes())
			if w.Code != http.StatusCreated {
				t.Fatalf("initial publish: %d %s", w.Code, w.Body.String())
			}
			slow := &stalledSiteWriter{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(slow.release) })
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				srv.handlePublic(slow, httptest.NewRequest("GET", "https://docs.example.com"+path, nil))
			}()
			// Always release the stalled client before database/temp-dir cleanup,
			// including when the old locking behavior makes this test fail.
			defer func() { release(); <-finished }()
			select {
			case <-slow.started:
			case <-time.After(5 * time.Second):
				t.Fatal("static response did not start")
			}
			cleanup := make(chan error, 1)
			go func() { cleanup <- srv.cleanupPublishedSites(context.Background()) }()
			select {
			case err := <-cleanup:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("stalled response blocked publication cleanup")
			}
			w = incrementalSiteRequest(srv, "GET", serviceapi.Sites+"/files?domain=docs", "owner", "", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("file comparison: %d %s", w.Code, w.Body.String())
			}
			// Replacing the publication may close its cached root and remove the
			// old directory, but the stalled request must retain its open file.
			writeIncrementalTestFile(t, root, "index.html", "replacement")
			archive.Reset()
			if err := publish.Archive(root, &archive); err != nil {
				t.Fatal(err)
			}
			w = incrementalSiteRequest(srv, "POST", serviceapi.Sites+"?domain=docs", "owner", "", archive.Bytes())
			if w.Code != http.StatusOK {
				t.Fatalf("republish: %d %s", w.Code, w.Body.String())
			}
			next := httptest.NewRecorder()
			srv.handlePublic(next, httptest.NewRequest("GET", "https://docs.example.com/", nil))
			if next.Code != http.StatusOK || next.Body.String() != "replacement" {
				t.Fatalf("new static request: %d %q", next.Code, next.Body.String())
			}
			release()
			<-finished
			if path == "/missing.js" || path == "/.env" {
				if slow.Code != http.StatusNotFound {
					t.Fatalf("missing or blocked file returned %d", slow.Code)
				}
			} else if slow.Body.String() != original {
				t.Fatal("republish interrupted the original file response")
			}
		})
	}
}

type stalledSiteWriter struct {
	*httptest.ResponseRecorder
	started, release chan struct{}
	once             sync.Once
}

func (w *stalledSiteWriter) WriteHeader(status int) {
	w.once.Do(func() { close(w.started); <-w.release })
	w.ResponseRecorder.WriteHeader(status)
}
