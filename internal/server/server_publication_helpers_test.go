package server

import (
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func TestPublicRouteLookupErrorStatus(t *testing.T) {
	t.Parallel()

	status, msg := publicRouteLookupErrorStatus(sql.ErrNoRows)
	if status != http.StatusNotFound || msg != "unknown host" {
		t.Fatalf("sql.ErrNoRows = (%d, %q), want (404, unknown host)", status, msg)
	}
	status, msg = publicRouteLookupErrorStatus(errors.New("boom"))
	if status != http.StatusInternalServerError || msg != "internal error" {
		t.Fatalf("generic error = (%d, %q), want (500, internal error)", status, msg)
	}
}

func TestWebSocketReadLimitFor(t *testing.T) {
	t.Parallel()

	if got := webSocketReadLimitFor(config.ServerConfig{}); got != int64(minWSReadLimit) {
		t.Fatalf("zero config limit = %d, want floor %d", got, minWSReadLimit)
	}
	large := int64(minWSReadLimit)
	if got := webSocketReadLimitFor(config.ServerConfig{MaxBodyBytes: large}); got != large*2 {
		t.Fatalf("large body limit = %d, want %d", got, large*2)
	}
}

func TestShouldInspectWAFBody(t *testing.T) {
	t.Parallel()

	if shouldInspectWAFBody(nil) {
		t.Fatal("nil request must not be inspected")
	}
	for path, want := range map[string]bool{
		"/healthz":     false,
		"/v1/register": false,
		"/":            true,
		"/api/data":    true,
	} {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		if got := shouldInspectWAFBody(r); got != want {
			t.Fatalf("shouldInspectWAFBody(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestNextIDsUnique(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	req := srv.nextRequestID()
	ws := srv.nextWSStreamID()
	if !strings.HasPrefix(req, "req_") {
		t.Fatalf("request ID %q missing req_ prefix", req)
	}
	if !strings.HasPrefix(ws, "ws_") {
		t.Fatalf("stream ID %q missing ws_ prefix", ws)
	}
	if ws2 := srv.nextWSStreamID(); ws2 == ws {
		t.Fatalf("expected unique stream IDs, got %q twice", ws)
	}
}

func TestNewH3SessionToken(t *testing.T) {
	t.Parallel()

	a, err := newH3SessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a, "h3_") || len(a) != len("h3_")+64 {
		t.Fatalf("token %q, want h3_ prefix and 64 hex chars", a)
	}
	b, err := newH3SessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected unique tokens")
	}
}

func TestSessionH3Helpers(t *testing.T) {
	t.Parallel()

	var nilSess *session
	if nilSess.hasH3MultiStream() || nilSess.usesH3StreamV2() {
		t.Fatal("nil session must report no H3 capabilities")
	}
	sess := &session{h3StreamV2: true}
	if !sess.usesH3StreamV2() {
		t.Fatal("expected h3StreamV2 session to report V2")
	}
	if sess.hasH3MultiStream() {
		t.Fatal("session without stream pool must not report multi-stream")
	}
}

func TestIsHostnameInUseError(t *testing.T) {
	t.Parallel()

	if !isHostnameInUseError(sqlite.ErrHostnameInUse) {
		t.Fatal("expected sqlite.ErrHostnameInUse to match")
	}
	if isHostnameInUseError(errors.New("other")) {
		t.Fatal("expected unrelated error not to match")
	}
}

func TestLogDroppedQueueEventsResetsCounters(t *testing.T) {
	t.Parallel()

	srv := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv.wafAuditDrops.Store(3)
	srv.domainTouchDrops.Store(2)
	srv.disconnectDrops.Store(1)
	srv.logDroppedQueueEvents()
	if srv.wafAuditDrops.Load() != 0 || srv.domainTouchDrops.Load() != 0 || srv.disconnectDrops.Load() != 0 {
		t.Fatal("expected drop counters to reset after logging")
	}
	srv.logDroppedQueueEvents()
}

func TestCleanupStaleH3Sessions(t *testing.T) {
	t.Parallel()

	srv := &Server{cfg: config.ServerConfig{ClientPingTimeout: time.Minute}}

	fresh := &session{tunnelID: "t-fresh"}
	fresh.lastSeenUnixNano.Store(time.Now().UnixNano())
	stale := &session{tunnelID: "t-stale"}
	stale.lastSeenUnixNano.Store(time.Now().Add(-time.Hour).UnixNano())

	srv.h3Sessions.Store("fresh", fresh)
	srv.h3Sessions.Store("stale", stale)
	srv.h3Sessions.Store("bogus", "not-a-session")

	srv.cleanupStaleH3Sessions()

	if _, ok := srv.h3Sessions.Load("fresh"); !ok {
		t.Fatal("expected fresh session to survive cleanup")
	}
	if _, ok := srv.h3Sessions.Load("stale"); ok {
		t.Fatal("expected stale session to be removed")
	}
	if _, ok := srv.h3Sessions.Load("bogus"); ok {
		t.Fatal("expected non-session value to be removed")
	}
}

func newPublicationTestServer() *Server {
	return &Server{
		liveRoutes: newLiveRouteIndex(),
		routes: routeCache{
			entries:       make(map[string]routeCacheEntry),
			hostsByTunnel: make(map[string]map[string]struct{}),
		},
	}
}

func TestPublishRouteMiss(t *testing.T) {
	t.Parallel()

	srv := newPublicationTestServer()
	host := "miss.example.com"
	version := srv.routeVersions.current(host)

	if !srv.publishRouteMiss(host, version) {
		t.Fatal("expected miss publication at current version to succeed")
	}
	if _, found, ok := srv.routes.lookup(host); !ok || found {
		t.Fatalf("lookup after miss = (found=%v, cached=%v), want cached miss", found, ok)
	}

	srv.publishRegisteredRoute(domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-1", Hostname: host},
		Tunnel: domain.Tunnel{ID: "t-1"},
	})
	if srv.publishRouteMiss(host, version) {
		t.Fatal("expected stale-version miss publication to be rejected")
	}
	if _, ok := srv.routes.get(host); !ok {
		t.Fatal("expected registered route to survive stale miss publication")
	}
}

func TestAttachAndClearPublishedSession(t *testing.T) {
	t.Parallel()

	srv := newPublicationTestServer()
	host := "attach.example.com"
	route := domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-1", Hostname: host, Status: domain.DomainStatusActive},
		Tunnel: domain.Tunnel{ID: "t-1"},
	}
	srv.publishRegisteredRoute(route)
	if _, ok := srv.liveRoutes.lookupHost(host); ok {
		t.Fatal("registered route should remain cached until a session is attached")
	}

	sess := &session{tunnelID: route.Tunnel.ID}
	srv.attachPublishedSession(route.Tunnel.ID, sess)
	snap, ok := srv.liveRoutes.lookupHost(host)
	if !ok || snap.session != sess {
		t.Fatal("expected session to be attached to live route")
	}

	if !srv.clearPublishedSession(route.Tunnel.ID, sess) {
		t.Fatal("expected clearPublishedSession to report success")
	}
	if _, ok = srv.liveRoutes.lookupHost(host); ok {
		t.Fatal("expected disconnected session to be evicted from live routes")
	}

	// Unknown tunnels are a no-op for attach and report failure for clear.
	srv.attachPublishedSession("t-unknown", sess)
	if srv.clearPublishedSession("t-unknown", sess) {
		t.Fatal("expected clear of unknown tunnel to fail")
	}
}
