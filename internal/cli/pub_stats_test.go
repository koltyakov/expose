package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/termui"
)

func TestPubStatsReconnectAndPublicationIdentity(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer owner" {
			t.Errorf("unexpected stats request: %s", r.Method)
		}
		if calls <= 2 && r.URL.Path != "/v1/sites/docs/stats" {
			t.Errorf("initial selection: %s", r.URL.Path)
		}
		if calls > 2 && r.URL.Path != "/v1/sites/site_original/stats" {
			t.Errorf("connection did not pin publication identity: %s", r.URL.Path)
		}
		if calls == 1 {
			w.WriteHeader(503)
			return
		}
		if calls == 4 {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(domain.PublishedSiteStats{Site: domain.PublishedSite{ID: "site_original", Hostname: "docs.example.com"}, HTTPRequests: int64(calls)})
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	err := connectPublishedSite(ctx, server.Client(), server.URL+"/v1/sites", "owner", "docs", &output, false, true, time.Millisecond)
	var status pubStatsHTTPError
	if !errors.As(err, &status) || status.status != 404 {
		t.Fatalf("expected deleted site to stop connection: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two snapshots, got %s", output.String())
	}
	for _, line := range lines {
		var stats domain.PublishedSiteStats
		if err := json.Unmarshal([]byte(line), &stats); err != nil {
			t.Fatalf("invalid NDJSON: %v", err)
		}
	}
}

func TestPubConnectFolderAndDomain(t *testing.T) {
	t.Chdir(t.TempDir())
	folder := t.TempDir()
	source, err := publishedFolderID(folder)
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range [][]string{{"--domain=docs"}, {folder}} {
		t.Run(strings.Join(selector, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			polls, lookups := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("connect changed hosting: %s", r.Method)
				}
				if r.Header.Get("Authorization") != "Bearer owner" {
					t.Error("stats request missing ownership credentials")
				}
				site := domain.PublishedSite{ID: "site_live", Hostname: "docs.example.com", SourceID: source}
				if r.URL.Path == "/v1/sites" {
					lookups++
					_ = json.NewEncoder(w).Encode([]domain.PublishedSite{site})
					return
				}
				polls++
				if polls > 1 {
					cancel()
					return
				}
				want := "/v1/sites/docs/stats"
				if selector[0] == folder {
					want = "/v1/sites/site_live/stats"
				}
				if r.URL.Path != want {
					t.Errorf("wrong selection: %s, want %s", r.URL.Path, want)
				}
				_ = json.NewEncoder(w).Encode(domain.PublishedSiteStats{Site: site})
			}))
			defer server.Close()
			original := http.DefaultTransport
			http.DefaultTransport = server.Client().Transport
			defer func() { http.DefaultTransport = original }()
			args := append([]string{"connect"}, selector...)
			args = append(args, "--server", server.URL, "--api-key", "owner", "--json")
			if err := pubCommand(ctx, args); err != nil {
				t.Fatal(err)
			}
			if polls != 2 {
				t.Fatalf("did not poll until disconnect: %d", polls)
			}
			if selector[0] == folder && lookups != 1 {
				t.Fatal("folder was not resolved")
			}
		})
	}
}

func TestPubStatsDisplayAndCleanup(t *testing.T) {
	var output bytes.Buffer
	display := pubStatsDisplay{out: &output, interactive: true}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	stats := domain.PublishedSiteStats{
		Site: domain.PublishedSite{Hostname: "docs.example.com", ExpiresAt: &expires}, Since: now, CapturedAt: now,
		HTTPRequests: 2, ResponseBytes: 1024, Visitors: 1, ActiveVisitors: 1, WAFEnabled: true, WAFBlocked: 1,
		Requests: []domain.PublishedSiteRequest{{Time: now, Method: "GET", Path: "/\x1b[2Jinjected", Status: 200}},
	}
	if err := display.render(stats, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	stats.CapturedAt = now.Add(time.Second)
	stats.ResponseBytes += 2048
	if err := display.render(stats, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	display.close()
	for _, text := range []string{"docs.example.com", "Expires", "HTTP Requests", "Visitors", "2.0 KiB/s", "Request latency", "blocked 1", termui.ShowCur} {
		if !strings.Contains(output.String(), text) {
			t.Errorf("dashboard missing %q", text)
		}
	}
	if strings.Contains(output.String(), "\x1b[2J") {
		t.Fatal("request injected terminal control codes")
	}
}
