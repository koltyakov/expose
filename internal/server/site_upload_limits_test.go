package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func assertNoActiveSiteUploads(t *testing.T, srv *Server) {
	t.Helper()
	srv.siteUploads.mu.Lock()
	defer srv.siteUploads.mu.Unlock()
	if srv.siteUploads.active != 0 || len(srv.siteUploads.byKey) != 0 {
		t.Fatalf("upload slots leaked: total %d, keys %v", srv.siteUploads.active, srv.siteUploads.byKey)
	}
}

func TestSiteUploadLimiterConcurrentBounds(t *testing.T) {
	var limiter siteUploadLimiter
	type admitted struct {
		key     string
		release func()
	}
	accepted := make(chan admitted, 32)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			key := fmt.Sprint(i % 4)
			release, _ := limiter.acquire(key, 3, 1)
			if release != nil {
				accepted <- admitted{key, release}
			}
		})
	}
	wg.Wait()
	close(accepted)
	if len(accepted) != 3 {
		t.Fatalf("admitted %d, want exactly 3", len(accepted))
	}
	keys := make(map[string]bool)
	for upload := range accepted {
		if keys[upload.key] {
			t.Fatalf("key %s exceeded its limit", upload.key)
		}
		keys[upload.key] = true
		upload.release()
		upload.release() // Releases are idempotent.
	}
	if limiter.active != 0 || len(limiter.byKey) != 0 {
		t.Fatalf("release leaked state: %d, %v", limiter.active, limiter.byKey)
	}
}

func TestSiteUploadLimiterDefaultBounds(t *testing.T) {
	var limiter siteUploadLimiter
	for i := range config.DefaultPublishMaxConcurrentUploads {
		release, status := limiter.acquire(fmt.Sprint(i/config.DefaultPublishMaxConcurrentUploadsPerKey), 0, 0)
		if release == nil {
			t.Fatalf("default upload %d rejected with %d", i, status)
		}
		defer release()
	}
	if release, status := limiter.acquire("0", 0, 0); release != nil || status != http.StatusTooManyRequests {
		t.Fatalf("default per-key cap not enforced: %v, %d", release != nil, status)
	}
	if release, status := limiter.acquire("new", 0, 0); release != nil || status != http.StatusServiceUnavailable {
		t.Fatalf("default global cap not enforced: %v, %d", release != nil, status)
	}
}

// gateUploadBody reports when extraction starts, then waits for permission or
// cancellation. Rejected requests must never call its Read method.
type gateUploadBody struct {
	io.Reader
	started chan struct{}
	proceed chan struct{}
	ctx     context.Context
	once    sync.Once
	err     error
}

func (b *gateUploadBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-b.proceed:
		if b.err != nil {
			return 0, b.err
		}
		return b.Reader.Read(p)
	}
}

func (b *gateUploadBody) Close() error { return nil }

func TestSiteUploadAdmissionLimits(t *testing.T) {
	for _, tc := range []struct {
		name         string
		global       int
		perKey       int
		admittedKeys []string
		rejectedKey  string
		wantStatus   int
	}{
		{"per-key", 3, 1, []string{"owner"}, "owner", http.StatusTooManyRequests},
		{"global", 2, 2, []string{"owner", "other"}, "other", http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newIncrementalTestServer(t)
			srv.cfg.PublishMaxConcurrentUploads = tc.global
			srv.cfg.PublishMaxConcurrentUploadsPerKey = tc.perKey
			root := t.TempDir()
			writeIncrementalTestFile(t, root, "index.html", "published")
			var archive bytes.Buffer
			if err := publish.Archive(root, &archive); err != nil {
				t.Fatal(err)
			}
			var completed []<-chan *httptest.ResponseRecorder
			var cancels []context.CancelFunc
			for i, key := range tc.admittedKeys {
				ctx, cancel := context.WithCancel(context.Background())
				cancels = append(cancels, cancel)
				body := &gateUploadBody{Reader: bytes.NewReader(archive.Bytes()), started: make(chan struct{}), proceed: make(chan struct{}), ctx: ctx}
				req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("%s?domain=site%d", serviceapi.Sites, i), body).WithContext(ctx)
				req.Header.Set("Authorization", "Bearer "+key)
				done := make(chan *httptest.ResponseRecorder, 1)
				finished := make(chan struct{})
				go func() {
					defer close(finished)
					w := httptest.NewRecorder()
					srv.handleSites(w, req)
					done <- w
				}()
				t.Cleanup(func() {
					cancel()
					select {
					case <-finished:
					case <-time.After(3 * time.Second):
						t.Error("upload did not exit after cancellation")
					}
				})
				completed = append(completed, done)
				select {
				case <-body.started:
				case w := <-done:
					t.Fatalf("upload rejected: %d %s", w.Code, w.Body.String())
				case <-time.After(3 * time.Second):
					t.Fatal("upload did not start extraction")
				}
			}
			for _, incremental := range []bool{false, true} {
				path := serviceapi.Sites + "?domain=rejected"
				if incremental {
					path += "&incremental=true"
				}
				body := &gateUploadBody{started: make(chan struct{}), ctx: context.Background()}
				req := httptest.NewRequest(http.MethodPost, path, body)
				req.Header.Set("Authorization", "Bearer "+tc.rejectedKey)
				req.Header.Set("If-Match", `"new"`)
				w := httptest.NewRecorder()
				srv.handleSites(w, req)
				if w.Code != tc.wantStatus || w.Header().Get("Retry-After") != "1" || w.Header().Get("Connection") != "close" {
					t.Fatalf("admission response: %d %v %s", w.Code, w.Header(), w.Body.String())
				}
				select {
				case <-body.started:
					t.Fatal("rejected upload read its body")
				default:
				}
				entries, err := os.ReadDir(srv.publishDir())
				if err != nil || len(entries) != len(completed) {
					t.Fatalf("rejection allocated staging files: %v, %v", entries, err)
				}
			}
			if tc.name == "per-key" {
				// A busy key must not block another key while global slots remain.
				w := incrementalSiteRequest(srv, http.MethodPost, serviceapi.Sites+"?domain=other", "other", "", archive.Bytes())
				if w.Code != http.StatusCreated {
					t.Fatalf("other key rejected: %d %s", w.Code, w.Body.String())
				}
			}
			for _, cancel := range cancels {
				cancel()
			}
			for _, done := range completed {
				select {
				case w := <-done:
					if w.Code != http.StatusBadRequest {
						t.Fatalf("canceled upload: %d %s", w.Code, w.Body.String())
					}
				case <-time.After(3 * time.Second):
					t.Fatal("canceled upload did not exit")
				}
			}
			assertNoActiveSiteUploads(t, srv)
			// Capacity is available again after all canceled uploads finish.
			w := incrementalSiteRequest(srv, http.MethodPost, serviceapi.Sites+"?domain=retry", tc.rejectedKey, "", archive.Bytes())
			if w.Code != http.StatusCreated {
				t.Fatalf("retry rejected: %d %s", w.Code, w.Body.String())
			}
			assertNoActiveSiteUploads(t, srv)
		})
	}
}

func TestSiteUploadAdmissionReleasedOnEveryExit(t *testing.T) {
	for _, outcome := range []string{"success", "invalid-archive", "timeout", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			srv, _ := newIncrementalTestServer(t)
			srv.cfg.PublishMaxConcurrentUploads = 1
			srv.cfg.PublishMaxConcurrentUploadsPerKey = 1
			root := t.TempDir()
			writeIncrementalTestFile(t, root, "index.html", "published")
			var archive bytes.Buffer
			if err := publish.Archive(root, &archive); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &gateUploadBody{Reader: bytes.NewReader(archive.Bytes()), started: make(chan struct{}), proceed: make(chan struct{}), ctx: ctx}
			req := httptest.NewRequest(http.MethodPost, serviceapi.Sites+"?domain=docs", body)
			req.Header.Set("Authorization", "Bearer owner")
			key, ok := srv.authenticate(req)
			if !ok {
				t.Fatal("failed to authenticate test key")
			}
			wantStatus := http.StatusCreated
			switch outcome {
			case "invalid-archive":
				body.err, wantStatus = errors.New("invalid archive"), http.StatusBadRequest
			case "timeout":
				body.err, wantStatus = os.ErrDeadlineExceeded, http.StatusRequestTimeout
			case "cancel":
				cancel()
				wantStatus = http.StatusBadRequest
			}
			close(body.proceed)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			// Direct invocation keeps cancellation from failing authentication first.
			srv.uploadSite(w, req, srv.store.(siteStore), key)
			if w.Code != wantStatus {
				t.Fatalf("upload: %d %s, want %d", w.Code, w.Body.String(), wantStatus)
			}
			assertNoActiveSiteUploads(t, srv)
			entries, err := os.ReadDir(srv.publishDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".upload-") {
					t.Fatalf("staging directory leaked: %s", entry.Name())
				}
			}
			w = incrementalSiteRequest(srv, http.MethodPost, serviceapi.Sites+"?domain=retry", "owner", "", archive.Bytes())
			if w.Code != http.StatusCreated {
				t.Fatalf("retry not admitted: %d %s", w.Code, w.Body.String())
			}
			assertNoActiveSiteUploads(t, srv)
		})
	}
}

func TestSiteUploadAdmissionRejectsStalledBodiesOverHTTP(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, perKey := range []bool{false, true} {
			t.Run(fmt.Sprintf("h2=%t/per-key=%t", h2, perKey), func(t *testing.T) {
				t.Parallel()
				srv, _ := newIncrementalTestServer(t)
				srv.cfg.RequestTimeout = 5 * time.Second
				srv.cfg.PublishMaxConcurrentUploads = 1
				srv.cfg.PublishMaxConcurrentUploadsPerKey = 1
				srv.cfg.PublishDir = t.TempDir() + "/not-created"
				authReq := httptest.NewRequest(http.MethodPost, serviceapi.Sites, nil)
				authReq.Header.Set("Authorization", "Bearer owner")
				key, ok := srv.authenticate(authReq)
				if !ok {
					t.Fatal("failed to authenticate test key")
				}
				release, _ := srv.siteUploads.acquire(key, 1, 1)
				defer release()
				server := httptest.NewUnstartedServer(srv.httpHandler())
				server.EnableHTTP2 = h2
				server.StartTLS()
				defer server.Close()
				reader, writer := io.Pipe()
				defer func() { _ = reader.Close() }()
				defer func() { _ = writer.Close() }()
				req, err := http.NewRequest(http.MethodPost, server.URL+serviceapi.Sites, reader)
				if err != nil {
					t.Fatal(err)
				}
				token, wantStatus := "other", http.StatusServiceUnavailable
				if perKey {
					token, wantStatus = "owner", http.StatusTooManyRequests
				}
				req.Header.Set("Authorization", "Bearer "+token)
				req.ContentLength = 1024
				go func() { _, _ = writer.Write([]byte("x")) }()
				client := server.Client()
				client.Timeout = 2 * time.Second
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != wantStatus || resp.Header.Get("Retry-After") != "1" {
					t.Fatalf("stalled rejection: %s %s %v, %v", resp.Status, body, resp.Header, err)
				}
				if h2 && resp.ProtoMajor != 2 {
					t.Fatalf("expected HTTP/2, got %s", resp.Proto)
				}
				if _, err := os.Stat(srv.publishDir()); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected request created storage: %v", err)
				}
				release()
				assertNoActiveSiteUploads(t, srv)
			})
		}
	}
}
