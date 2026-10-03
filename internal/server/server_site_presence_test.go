package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

func TestPublishedSitePresenceLifecycle(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	root := t.TempDir()
	writeIncrementalTestFile(t, root, "index.html", "<!doctype html><html><body>site</body></html>")
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	upload := func(query string) domain.PublishedSite {
		t.Helper()
		w := incrementalSiteRequest(srv, "POST", "/v1/sites?domain=docs"+query, "owner", "", archive.Bytes())
		var site domain.PublishedSite
		if (w.Code != 200 && w.Code != 201) || json.Unmarshal(w.Body.Bytes(), &site) != nil {
			t.Fatalf("upload: %d %s", w.Code, w.Body.String())
		}
		return site
	}
	plain := upload("")
	if plain.WS {
		t.Fatal("presence enabled by default")
	}
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://docs.example.com"+path, nil)
		r.Header.Set("User-Agent", "browser")
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		srv.handlePublic(w, r)
		return w
	}
	if strings.Contains(get("/").Body.String(), publish.PresenceScriptPath) {
		t.Fatal("default publication was injected")
	}
	for _, value := range []string{"invalid", ""} {
		w := incrementalSiteRequest(srv, "POST", "/v1/sites?domain=docs&ws="+value, "owner", "", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid ws accepted: %d", w.Code)
		}
	}
	site := upload("&ws=true")
	if !site.WS || site.ID != plain.ID {
		t.Fatalf("incorrect publication: %+v", site)
	}
	stored, err := st.FindPublishedSite(context.Background(), site.Hostname)
	if err != nil || !stored.WS {
		t.Fatalf("WS setting not persisted: %+v %v", stored, err)
	}
	if !strings.Contains(get("/").Body.String(), publish.PresenceScriptPath) {
		t.Fatal("enabled publication was not injected")
	}
	stats := srv.statsForSite(site.ID)
	before := stats.snapshot(time.Now())
	if js := get(publish.PresenceScriptPath); js.Code != 200 || !strings.Contains(js.Body.String(), "new WebSocket") {
		t.Fatalf("missing client script: %d %s", js.Code, js.Body.String())
	}
	server := httptest.NewServer(http.HandlerFunc(srv.handlePublic))
	defer server.Close()
	defer srv.closeSitePresence(site.ID)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + publish.PresencePath
	dial := func(origin string) (*websocket.Conn, *http.Response, error) {
		return websocket.DefaultDialer.Dial(wsURL, http.Header{
			"Host": {site.Hostname}, "Origin": {origin}, "User-Agent": {"browser"},
		})
	}
	for _, origin := range []string{"", "http://other.example.com", "null"} {
		conn, resp, err := dial(origin)
		if conn != nil {
			_ = conn.Close()
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q accepted: %v", origin, err)
		}
	}
	conn, _, err := dial("http://" + site.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ping := make(chan string, 1)
	conn.SetPingHandler(func(data string) error {
		ping <- data
		return nil
	})
	done := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadMessage()
		done <- err
	}()
	var payload string
	select {
	case payload = <-ping:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not start heartbeat")
	}
	// Simulate a page that has not downloaded anything for several minutes.
	stats.mu.Lock()
	for visitor := range stats.visitors {
		stats.visitors[visitor] = time.Now().Add(-2 * time.Minute)
	}
	stats.mu.Unlock()
	if stats.snapshot(time.Now()).ActiveVisitors != 0 {
		t.Fatal("old file request is still active")
	}
	if err := conn.WriteControl(websocket.PongMessage, []byte(payload), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for stats.snapshot(time.Now()).ActiveSockets != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	after := stats.snapshot(time.Now())
	if after.ActiveSockets != 1 || after.ActiveVisitors != 1 || after.Visitors != before.Visitors || after.HTTPRequests != before.HTTPRequests || after.ResponseBytes != before.ResponseBytes {
		t.Fatalf("heartbeat should refresh the same visitor without file traffic: before=%+v after=%+v", before, after)
	}
	// Republishing must not block on an open socket and keeps presence alive.
	upload("&ws=true")
	select {
	case err := <-done:
		t.Fatalf("republish disconnected presence: %v", err)
	default:
	}
	// Another visible tab shares the visitor identity but adds an online socket.
	second, _, err := dial("http://" + site.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	secondDone := make(chan struct{})
	go func() {
		_, _, _ = second.ReadMessage()
		close(secondDone)
	}()
	waitPresence := func(connections int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			got := stats.snapshot(time.Now())
			if got.ActiveSockets == connections && got.Visitors == before.Visitors {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("presence: sockets=%d visitors=%d, want %d and %d", got.ActiveSockets, got.Visitors, connections, before.Visitors)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitPresence(2)
	get("/") // A recent download must not mask the subsequent disconnect.
	if err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "inactive"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("first tab did not close")
	}
	waitPresence(1)
	if err := second.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "inactive"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondDone:
	case <-time.After(3 * time.Second):
		t.Fatal("second tab did not close")
	}
	waitPresence(0)
	if stats.snapshot(time.Now()).ActiveVisitors != 1 {
		t.Fatal("recent visitor activity was lost when its sockets closed")
	}
	// Returning to the tab reconnects without another file download.
	resumed, _, err := dial("http://" + site.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resumed.Close() }()
	resumedDone := make(chan struct{})
	go func() {
		_, _, _ = resumed.ReadMessage()
		close(resumedDone)
	}()
	waitPresence(1)
	// Publishing without --ws disables it and closes existing connections.
	disabled := upload("")
	if disabled.WS {
		t.Fatal("presence was not disabled")
	}
	select {
	case <-resumedDone:
	case <-time.After(3 * time.Second):
		t.Fatal("disabled publication retained its socket")
	}
	if strings.Contains(get("/").Body.String(), publish.PresenceScriptPath) {
		t.Fatal("disabled publication still injects HTML")
	}
	if got := stats.snapshot(time.Now()); got.ActiveSockets != 0 {
		t.Fatalf("disconnected socket is still online: %+v", got)
	}
}

func TestSitePresenceHeartbeatAndTimeout(t *testing.T) {
	for _, mode := range []string{"responsive", "unresponsive", "application-data", "deleted", "expired"} {
		t.Run(mode, func(t *testing.T) {
			srv, st := newIncrementalTestServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv.runtimeCtx.Store(ctx)
			root := t.TempDir()
			writeIncrementalTestFile(t, root, "index.html", "site")
			var archive bytes.Buffer
			if err := publish.Archive(root, &archive); err != nil {
				t.Fatal(err)
			}
			w := incrementalSiteRequest(srv, "POST", "/v1/sites?domain=docs&ws=true", "owner", "", archive.Bytes())
			var site domain.PublishedSite
			if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &site) != nil {
				t.Fatalf("upload: %d %s", w.Code, w.Body.String())
			}
			stats := srv.statsForSite(site.ID)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upgrader := websocket.Upgrader{}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err == nil {
					stats.mu.Lock()
					stats.presence = map[*websocket.Conn]sitePresence{conn: {fingerprint: [32]byte{1}}}
					stats.mu.Unlock()
					srv.runSitePresence(conn, site, stats, [32]byte{1}, 25*time.Millisecond, 250*time.Millisecond)
				}
			}))
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			pings := make(chan struct{}, 64)
			conn.SetPingHandler(func(data string) error {
				pings <- struct{}{}
				if mode != "unresponsive" {
					return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
				}
				return nil
			})
			done := make(chan struct{})
			go func() {
				_, _, _ = conn.ReadMessage()
				close(done)
			}()
			if mode == "responsive" {
				// Stay connected beyond the initial read deadline using only pongs.
				for range 12 {
					select {
					case <-pings:
					case <-done:
						t.Fatal("responsive client timed out")
					case <-time.After(3 * time.Second):
						t.Fatal("periodic ping missing")
					}
				}
				got := stats.snapshot(time.Now())
				if got.ActiveSockets != 1 || got.ActiveVisitors != 1 || got.HTTPRequests != 0 {
					t.Fatalf("cached-page activity missing or counted as HTTP: %+v", got)
				}
				cancel()
			} else if mode == "application-data" {
				if err := conn.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("x", 100))); err != nil {
					t.Fatal(err)
				}
			} else if mode == "deleted" {
				w := incrementalSiteRequest(srv, "DELETE", "/v1/sites/docs", "owner", "", nil)
				if w.Code != http.StatusNoContent {
					t.Fatalf("delete: %d %s", w.Code, w.Body.String())
				}
			} else if mode == "expired" {
				stored, err := st.FindPublishedSite(ctx, site.Hostname)
				if err != nil {
					t.Fatal(err)
				}
				expired := time.Now().Add(-time.Minute)
				stored.ExpiresAt = &expired
				if err := st.ReplacePublishedSite(ctx, stored); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("%s socket did not close", mode)
			}
		})
	}
}
