package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func assertPublicRejection(t *testing.T, w *httptest.ResponseRecorder, status int, reason string) {
	t.Helper()
	if w.Code != status || w.Header().Get(serviceapi.ErrorHeader) != reason || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("rejection: status=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
	}
}

func TestPublicRejectionDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		reason, message string
		status          int
	}{
		{rejectionRateLimit, "rate limit exceeded", http.StatusTooManyRequests},
		{rejectionLookupRateLimit, "rate limit exceeded", http.StatusTooManyRequests},
		{rejectionConcurrency, "tunnel overloaded", http.StatusServiceUnavailable},
		{rejectionBackpressure, "tunnel overloaded", http.StatusServiceUnavailable},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			var logs bytes.Buffer
			srv := &Server{log: slog.New(slog.NewJSONHandler(&logs, nil))}
			r := httptest.NewRequest(http.MethodGet, "https://app.example.com/assets/hero.png?token=private-query", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("Authorization", "Bearer private-auth")
			r.Header.Set("Cookie", "session=private-cookie")
			w := httptest.NewRecorder()
			recorder := &siteStatsWriter{ResponseWriter: w}
			srv.writePublicRejection(recorder, r, tc.status, tc.message, tc.reason)
			assertPublicRejection(t, w, tc.status, tc.reason)
			if recorder.rejectionReason != tc.reason || w.Body.String() != tc.message+"\n" {
				t.Fatalf("incorrect history/body: %+v %q", recorder, w.Body.String())
			}
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry["reason"] != tc.reason || entry["path"] != "/assets/hero.png" || entry["domain"] != "app.example.com" || entry["remote"] != "192.0.2.1" {
				t.Fatalf("incorrect structured log: %s", logs.String())
			}
			if strings.Contains(logs.String(), "private-") || strings.Contains(logs.String(), "token") {
				t.Fatalf("log leaked credentials: %s", logs.String())
			}
		})
	}
}

func TestPublicRejectionLogSamplingPreservesResponses(t *testing.T) {
	var logs bytes.Buffer
	srv := &Server{
		log:                 slog.New(slog.NewJSONHandler(&logs, nil)),
		rejectionLogLimiter: newConfiguredRateLimiter(0, 1, 0),
	}
	for range 10 {
		w := httptest.NewRecorder()
		srv.writePublicRejection(w, httptest.NewRequest("GET", "/asset.png", nil), 429, "rate limit exceeded", rejectionRateLimit)
		assertPublicRejection(t, w, 429, rejectionRateLimit)
	}
	if count := strings.Count(logs.String(), "public request rejected"); count != 1 {
		t.Fatalf("expected one sampled log, got %d: %s", count, logs.String())
	}
}

func TestPublicConcurrencyRejectionsAcrossTransports(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*Server, http.ResponseWriter, *http.Request, domain.TunnelRoute, *session)
	}{
		{"http over websocket", (*Server).proxyPublicHTTP},
		{"http over h3", (*Server).proxyPublicHTTPH3MultiStream},
		{"websocket over websocket", (*Server).handlePublicWebSocket},
		{"websocket over h3", (*Server).handlePublicWebSocketH3MultiStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{cfg: config.ServerConfig{MaxPendingPerTunnel: 1}}
			sess := &session{}
			sess.pendingCount.Store(1)
			sess.webSocketCount.Store(1)
			w := httptest.NewRecorder()
			tc.run(srv, w, httptest.NewRequest("GET", "/asset.png", nil), domain.TunnelRoute{}, sess)
			assertPublicRejection(t, w, 503, rejectionConcurrency)
			if sess.pendingCount.Load() != 1 || sess.webSocketCount.Load() != 1 {
				t.Fatal("rejection leaked an in-flight slot")
			}
		})
	}
}

func TestPublishedSiteRateLimitReasonInHistory(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	keyID, err := st.ResolveAPIKeyID(context.Background(), auth.HashAPIKey("owner", ""))
	if err != nil {
		t.Fatal(err)
	}
	site := domain.PublishedSite{ID: "site_throttled", APIKeyID: keyID, Hostname: "app.example.com", CreatedAt: time.Now().UTC()}
	if err := st.CreatePublishedSite(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	srv.siteHosts.Store(site.Hostname, site)
	srv.publicLimiter = newConfiguredRateLimiter(0, 0, time.Minute)
	w := httptest.NewRecorder()
	srv.handlePublic(w, httptest.NewRequest("GET", "https://app.example.com/hero.png?token=private", nil))
	assertPublicRejection(t, w, 429, rejectionRateLimit)
	stats := srv.statsForSite(site.ID).snapshot(time.Now())
	if stats.HTTPRequests != 1 || stats.WAFBlocked != 0 || len(stats.Requests) != 1 {
		t.Fatalf("incorrect rate-limit stats: %+v", stats)
	}
	entry := stats.Requests[0]
	if entry.RejectionReason != rejectionRateLimit || entry.Path != "/hero.png" || entry.Status != 429 || entry.WAFRule != "" {
		t.Fatalf("incorrect request history: %+v", entry)
	}
}
