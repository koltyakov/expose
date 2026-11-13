package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func TestSiteUploadOutlivesOrdinaryDeadlines(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, incremental := range []bool{false, true} {
			name := "http1/full"
			if h2 {
				name = "http2/full"
			}
			if incremental {
				name = strings.TrimSuffix(name, "full") + "incremental"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				srv, st := newIncrementalTestServer(t)
				srv.cfg.RequestTimeout = 100 * time.Millisecond
				srv.cfg.PublishUploadIdleTimeout = 500 * time.Millisecond
				srv.cfg.WAFEnabled = true
				server := httptest.NewUnstartedServer(srv.httpHandler())
				server.Config.ReadTimeout = 100 * time.Millisecond
				server.Config.WriteTimeout = 100 * time.Millisecond
				server.EnableHTTP2 = h2
				server.StartTLS()
				defer server.Close()

				root := t.TempDir()
				writeIncrementalTestFile(t, root, "index.html", "slow upload")
				var archive bytes.Buffer
				path := serviceapi.Sites + "?domain=slow"
				if incremental {
					manifest, err := publish.Manifest(root)
					if err != nil {
						t.Fatal(err)
					}
					if err := publish.ArchiveDelta(root, &archive, manifest, nil, nil); err != nil {
						t.Fatal(err)
					}
					path += "&incremental=true"
				} else if err := publish.Archive(root, &archive); err != nil {
					t.Fatal(err)
				}
				reader, writer := io.Pipe()
				defer func() { _ = reader.Close() }()
				req, err := http.NewRequest(http.MethodPost, server.URL+path, reader)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer owner")
				if incremental {
					req.Header.Set("If-Match", `"new"`)
				}
				data := archive.Bytes()
				req.ContentLength = int64(len(data))
				go func() {
					defer func() { _ = writer.Close() }()
					// Total duration exceeds both ordinary deadlines and the
					// upload idle interval, but each read keeps progressing.
					const chunks = 6
					for i := range chunks {
						if i > 0 {
							time.Sleep(150 * time.Millisecond)
						}
						if _, err := writer.Write(data[len(data)*i/chunks : len(data)*(i+1)/chunks]); err != nil {
							return
						}
					}
				}()
				client := server.Client()
				client.Timeout = 5 * time.Second
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != http.StatusCreated {
					t.Fatalf("slow upload: %s %s, %v", resp.Status, body, err)
				}
				if h2 && resp.ProtoMajor != 2 {
					t.Fatalf("expected HTTP/2, got %s", resp.Proto)
				}
				if _, err := st.FindPublishedSite(context.Background(), "slow.example.com"); err != nil {
					t.Fatalf("upload was not committed: %v", err)
				}
			})
		}
	}
}

func TestSiteUploadTimeoutPreservesPublication(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	root := t.TempDir()
	writeIncrementalTestFile(t, root, "index.html", "original")
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	path := serviceapi.Sites + "?domain=docs"
	w := incrementalSiteRequest(srv, http.MethodPost, path, "owner", "", archive.Bytes())
	if w.Code != http.StatusCreated {
		t.Fatalf("initial upload: %d %s", w.Code, w.Body.String())
	}
	before, err := st.FindPublishedSite(context.Background(), "docs.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, incremental := range []bool{false, true} {
		requestPath := path
		if incremental {
			requestPath += "&incremental=true"
		}
		r := httptest.NewRequest(http.MethodPost, requestPath, nil)
		r.Header.Set("Authorization", "Bearer owner")
		r.Header.Set("If-Match", publishedSiteRevision(&before))
		r.Body = io.NopCloser(siteTimeoutReader{})
		w := httptest.NewRecorder()
		srv.httpHandler().ServeHTTP(w, r)
		if w.Code != http.StatusRequestTimeout || !strings.Contains(w.Body.String(), "site upload timed out") {
			t.Fatalf("timeout response: %d %s", w.Code, w.Body.String())
		}
		after, err := st.FindPublishedSite(context.Background(), before.Hostname)
		if err != nil || after.StorageID() != before.StorageID() {
			t.Fatalf("timeout replaced publication: %+v, %v", after, err)
		}
		entries, err := os.ReadDir(srv.publishDir())
		if err != nil || len(entries) != 1 {
			t.Fatalf("timeout left staging files: %v, %v", entries, err)
		}
	}
}

func TestSiteUploadIdleTimeoutOverHTTP(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, incremental := range []bool{false, true} {
			name := "http1/full"
			if h2 {
				name = "http2/full"
			}
			if incremental {
				name = strings.TrimSuffix(name, "full") + "incremental"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				srv, st := newIncrementalTestServer(t)
				srv.cfg.RequestTimeout = 2 * time.Second
				srv.cfg.PublishUploadIdleTimeout = 150 * time.Millisecond
				root := t.TempDir()
				writeIncrementalTestFile(t, root, "index.html", "original")
				var archive bytes.Buffer
				if err := publish.Archive(root, &archive); err != nil {
					t.Fatal(err)
				}
				path := serviceapi.Sites + "?domain=docs"
				w := incrementalSiteRequest(srv, http.MethodPost, path, "owner", "", archive.Bytes())
				if w.Code != http.StatusCreated {
					t.Fatalf("initial upload: %d %s", w.Code, w.Body.String())
				}
				before, err := st.FindPublishedSite(context.Background(), "docs.example.com")
				if err != nil {
					t.Fatal(err)
				}
				if incremental {
					path += "&incremental=true"
				}
				handler := srv.httpHandler()
				finished := make(chan struct{})
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					handler.ServeHTTP(w, r)
					close(finished)
				}))
				server.EnableHTTP2 = h2
				server.StartTLS()
				defer server.Close()
				reader, writer := io.Pipe()
				defer func() { _ = reader.Close() }()
				defer func() { _ = writer.Close() }()
				req, err := http.NewRequest(http.MethodPost, server.URL+path, reader)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer owner")
				req.Header.Set("If-Match", publishedSiteRevision(&before))
				req.ContentLength = int64(archive.Len())
				go func() { _, _ = writer.Write(archive.Bytes()[:1]) }()
				client := server.Client()
				client.Timeout = 3 * time.Second
				started := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != http.StatusRequestTimeout {
					t.Fatalf("stalled upload: %s %s, %v", resp.Status, body, err)
				}
				if h2 && resp.ProtoMajor != 2 {
					t.Fatalf("expected HTTP/2, got %s", resp.Proto)
				}
				if time.Since(started) >= 2*time.Second {
					t.Fatal("upload waited for ordinary deadline rather than idle timeout")
				}
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Fatal("timed-out upload handler did not exit")
				}
				assertNoActiveSiteUploads(t, srv)
				after, err := st.FindPublishedSite(context.Background(), before.Hostname)
				if err != nil || after.StorageID() != before.StorageID() {
					t.Fatalf("timeout replaced publication: %+v, %v", after, err)
				}
				content, err := os.ReadFile(srv.publishDir() + "/" + before.StorageID() + "/index.html")
				if err != nil || string(content) != "original" {
					t.Fatalf("timeout changed published content: %q, %v", content, err)
				}
				entries, err := os.ReadDir(srv.publishDir())
				if err != nil || len(entries) != 1 {
					t.Fatalf("timeout left staging files: %v, %v", entries, err)
				}
			})
		}
	}
}

type siteTimeoutReader struct{}

func (siteTimeoutReader) Read([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }

func TestSiteUploadIdleDeadlinesOnlyAfterAuthentication(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	srv.cfg.RequestTimeout = time.Second
	srv.cfg.PublishUploadIdleTimeout = 2 * time.Second
	for _, token := range []string{"owner", "invalid"} {
		r := httptest.NewRequest(http.MethodPost, serviceapi.Sites, strings.NewReader("invalid archive"))
		r.Header.Set("Authorization", "Bearer "+token)
		w := &siteDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
		srv.httpHandler().ServeHTTP(w, r)
		if token == "owner" {
			var idleReads int
			for _, deadline := range w.readDeadlines {
				if !deadline.IsZero() && time.Until(deadline) > time.Second && time.Until(deadline) <= 2*time.Second {
					idleReads++
				}
			}
			if idleReads < 2 || len(w.writeDeadlines) < 2 || !w.writeDeadlines[0].IsZero() || w.writeDeadlines[len(w.writeDeadlines)-1].IsZero() {
				t.Fatalf("upload deadlines not bounded: reads %v, writes %v", w.readDeadlines, w.writeDeadlines)
			}
		} else if w.Code != http.StatusUnauthorized || len(w.readDeadlines) != 2 || len(w.writeDeadlines) != 0 {
			t.Fatalf("unauthenticated request changed deadlines: %d, reads %v, writes %v", w.Code, w.readDeadlines, w.writeDeadlines)
		}
	}
}

type siteDeadlineWriter struct {
	*httptest.ResponseRecorder
	readDeadlines, writeDeadlines []time.Time
}

func (w *siteDeadlineWriter) SetReadDeadline(deadline time.Time) error {
	w.readDeadlines = append(w.readDeadlines, deadline)
	return nil
}

func (w *siteDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.writeDeadlines = append(w.writeDeadlines, deadline)
	return nil
}
