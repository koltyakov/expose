package server

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type testContextKey string

type limitStoreStub struct {
	limit int
	err   error
	calls int
}

func (s *limitStoreStub) GetAPIKeyTunnelLimit(context.Context, string) (int, error) {
	s.calls++
	return s.limit, s.err
}

func TestPendingRequestLifecycle(t *testing.T) {
	t.Parallel()

	req := acquirePendingRequest()
	defer releasePendingRequest(req)

	resp := &tunnelproto.HTTPResponse{ID: "req-1", Status: 200}
	if !req.deliverHeader(resp) {
		t.Fatal("deliverHeader() = false, want true")
	}
	got, ok := req.waitHeader(context.Background())
	if !ok || got == nil || got.ID != "req-1" {
		t.Fatalf("waitHeader() = %#v, %v", got, ok)
	}

	bodyCh := req.ensureBodyCh()
	streamCh, doneCh := req.bodyStream()
	if streamCh == nil {
		t.Fatal("bodyStream() returned nil body channel")
	}
	bodyCh <- []byte("chunk")
	req.finish()

	select {
	case <-doneCh:
	default:
		t.Fatal("doneCh should be closed after finish()")
	}

	if req.deliverHeader(resp) {
		t.Fatal("deliverHeader() after finish = true, want false")
	}

	req.reset()
	select {
	case <-req.doneCh:
		t.Fatal("reset() should create a fresh open doneCh")
	default:
	}
}

func TestPendingRequestWaitHeaderHandlesContextAndNil(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, ok := (*pendingRequest)(nil).waitHeader(context.Background()); ok || got != nil {
		t.Fatalf("nil waitHeader() = %#v, %v", got, ok)
	}

	req := acquirePendingRequest()
	defer releasePendingRequest(req)
	if got, ok := req.waitHeader(ctx); ok || got != nil {
		t.Fatalf("canceled waitHeader() = %#v, %v", got, ok)
	}
}

func TestActiveTunnelTrackerLifecycle(t *testing.T) {
	t.Parallel()

	tracker := newActiveTunnelTracker()
	store := &limitStoreStub{limit: 2}

	limit, err := tracker.limitFor(context.Background(), store, " key-1 ")
	if err != nil || limit != 2 {
		t.Fatalf("limitFor() = %d, %v", limit, err)
	}
	limit, err = tracker.limitFor(context.Background(), store, "key-1")
	if err != nil || limit != 2 {
		t.Fatalf("limitFor(cached) = %d, %v", limit, err)
	}
	if store.calls != 1 {
		t.Fatalf("expected cached limit lookup, calls = %d", store.calls)
	}
	if !tracker.canConnect("key-1", "tun-1", 2) {
		t.Fatal("canConnect() = false, want true")
	}

	tracker.markConnected("key-1", "tun-1")
	tracker.markConnected("key-1", "tun-1")
	if got := tracker.activeCount("key-1"); got != 1 {
		t.Fatalf("activeCount() = %d, want %d", got, 1)
	}
	if tracker.canConnect("key-1", "tun-2", 1) {
		t.Fatal("canConnect(limit reached) = true, want false")
	}

	tracker.markConnected("key-2", "tun-1")
	if got := tracker.activeCount("key-1"); got != 0 {
		t.Fatalf("activeCount(key-1) = %d, want 0", got)
	}
	if got := tracker.activeCount("key-2"); got != 1 {
		t.Fatalf("activeCount(key-2) = %d, want 1", got)
	}

	tracker.markDisconnected("tun-1")
	if got := tracker.activeCount("key-2"); got != 0 {
		t.Fatalf("activeCount(after disconnect) = %d, want 0", got)
	}
}

func TestLiveRouteIndexLifecycle(t *testing.T) {
	t.Parallel()

	idx := newLiveRouteIndex()
	route := domain.TunnelRoute{
		Domain: domain.Domain{
			ID:       "domain-1",
			APIKeyID: "key-1",
			Hostname: "app.example.com",
		},
		Tunnel: domain.Tunnel{
			ID:                 "tun-1",
			APIKeyID:           "key-1",
			DomainID:           "domain-1",
			IsTemporary:        true,
			State:              domain.TunnelStateConnected,
			AccessUser:         "admin",
			AccessMode:         "form",
			AccessPasswordHash: "hash-1",
		},
	}

	idx.upsert(route)

	hostSnap, ok := idx.lookupHost("APP.EXAMPLE.COM")
	if !ok || hostSnap.route.Tunnel.ID != "tun-1" {
		t.Fatalf("lookupHost() = %#v, %v", hostSnap, ok)
	}
	if hostSnap.route.Tunnel.State != domain.TunnelStateDisconnected {
		t.Fatalf("expected disconnected state before attach, got %q", hostSnap.route.Tunnel.State)
	}

	idx.setAccess("tun-1", "user", "basic", "hash-2")
	tunnelSnap, ok := idx.lookupTunnel("tun-1")
	if !ok || tunnelSnap.route.Tunnel.AccessMode != "basic" || tunnelSnap.route.Tunnel.AccessUser != "user" {
		t.Fatalf("lookupTunnel() = %#v, %v", tunnelSnap, ok)
	}

	sess := &session{}
	attached, ok := idx.attachSession("tun-1", sess)
	if !ok || attached.session != sess || attached.route.Tunnel.State != domain.TunnelStateConnected {
		t.Fatalf("attachSession() = %#v, %v", attached, ok)
	}
	if got := idx.hostsForTunnel("tun-1"); len(got) != 1 || got[0] != "app.example.com" {
		t.Fatalf("hostsForTunnel() = %#v", got)
	}
	if got := idx.snapshotSessions(); len(got) != 1 || got[0] != sess {
		t.Fatalf("snapshotSessions() = %#v", got)
	}

	if snap, ok := idx.clearSession("tun-1", &session{}); ok || snap.session != sess {
		t.Fatalf("clearSession(wrong session) = %#v, %v", snap, ok)
	}
	cleared, ok := idx.clearSession("tun-1", sess)
	if !ok || cleared.session != nil || cleared.route.Tunnel.State != domain.TunnelStateDisconnected {
		t.Fatalf("clearSession() = %#v, %v", cleared, ok)
	}
}

func TestLiveRouteIndexHostTrackingAndHelpers(t *testing.T) {
	t.Parallel()

	idx := newLiveRouteIndex()
	shard := &idx.hostShards[liveRouteShardIndex("app.example.com")]

	idx.trackHostKeyLocked(shard, "key-1", "app.example.com")
	if _, ok := shard.byKeyID["key-1"]["app.example.com"]; !ok {
		t.Fatal("trackHostKeyLocked() did not record host")
	}
	idx.untrackHostKeyLocked(shard, "key-1", "app.example.com")
	if _, ok := shard.byKeyID["key-1"]; ok {
		t.Fatal("untrackHostKeyLocked() did not remove empty key set")
	}

	if got := snapshotFromEntry(nil); got != (liveRouteSnapshot{}) {
		t.Fatalf("snapshotFromEntry(nil) = %#v, want zero value", got)
	}
	if got := tunnelStateForEntry(nil); got != "" {
		t.Fatalf("tunnelStateForEntry(nil) = %q, want empty string", got)
	}
}

func TestServerDisconnectQueueAndContextHelpers(t *testing.T) {
	t.Parallel()

	srv := &Server{
		disconnects: make(chan string, 2),
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	srv.queueTunnelDisconnect("tun-1")
	srv.queueTunnelDisconnect("tun-1")

	if got := <-srv.disconnects; got != "tun-1" {
		t.Fatalf("queued tunnel = %q, want %q", got, "tun-1")
	}
	select {
	case got := <-srv.disconnects:
		t.Fatalf("unexpected duplicate queued tunnel %q", got)
	default:
	}

	srv.completeDisconnectBatch([]string{"tun-1"})
	srv.queueTunnelDisconnect("tun-1")
	if got := <-srv.disconnects; got != "tun-1" {
		t.Fatalf("requeued tunnel = %q, want %q", got, "tun-1")
	}

	baseCtx := context.WithValue(context.Background(), testContextKey("k"), "v")
	srv.runtimeCtx.Store(baseCtx)
	if got := srv.serverContext().Value(testContextKey("k")); got != "v" {
		t.Fatalf("serverContext() value = %v, want %v", got, "v")
	}
	var nilCtx context.Context
	if got := contextOrBackground(nilCtx); got == nil {
		t.Fatal("contextOrBackground(nil) = nil, want background context")
	}
}

func TestActiveTunnelTrackerLimitForBlankKeyAndError(t *testing.T) {
	t.Parallel()

	tracker := newActiveTunnelTracker()
	if limit, err := tracker.limitFor(context.Background(), nil, ""); err != nil || limit != -1 {
		t.Fatalf("limitFor(blank) = %d, %v", limit, err)
	}

	store := &limitStoreStub{err: context.DeadlineExceeded}
	if _, err := tracker.limitFor(context.Background(), store, "key-1"); err == nil {
		t.Fatal("limitFor(error) = nil, want error")
	}
}

func TestPendingRequestAbortAndBodyChannelReuse(t *testing.T) {
	t.Parallel()

	req := acquirePendingRequest()
	defer releasePendingRequest(req)

	bodyCh1 := req.ensureBodyCh()
	bodyCh2 := req.ensureBodyCh()
	if bodyCh1 != bodyCh2 {
		t.Fatal("ensureBodyCh() should reuse the same channel")
	}

	req.abort()
	select {
	case <-req.doneCh:
	case <-time.After(time.Second):
		t.Fatal("abort() did not close doneCh")
	}
}
