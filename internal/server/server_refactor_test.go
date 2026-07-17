package server

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

type stubServerStore struct {
	setTunnelDisconnectedFn  func(context.Context, string) error
	closeTemporaryTunnelFn   func(context.Context, string) (string, bool, error)
	setTunnelsDisconnectedFn func(context.Context, []string) error
	findRouteByHostFn        func(context.Context, string) (domain.TunnelRoute, error)
}

func (s *stubServerStore) ResetConnectedTunnels(context.Context) (int64, error) {
	return 0, nil
}

func (s *stubServerStore) ActiveTunnelCountByKey(context.Context, string) (int, error) {
	return 0, nil
}

func (s *stubServerStore) GetAPIKeyTunnelLimit(context.Context, string) (int, error) {
	return -1, nil
}

func (s *stubServerStore) IsHostnameActive(context.Context, string) (bool, error) {
	return false, nil
}

func (s *stubServerStore) AllocateDomainAndTunnelWithClientMeta(context.Context, string, string, string, string, string) (domain.Domain, domain.Tunnel, error) {
	return domain.Domain{}, domain.Tunnel{}, nil
}

func (s *stubServerStore) SetTunnelAccessCredentials(context.Context, string, string, string, string) error {
	return nil
}

func (s *stubServerStore) CreateConnectToken(context.Context, string, time.Duration) (string, error) {
	return "", nil
}

func (s *stubServerStore) ConsumeConnectToken(context.Context, string) (string, error) {
	return "", nil
}

func (s *stubServerStore) SetTunnelConnected(context.Context, string) error {
	return nil
}

func (s *stubServerStore) TrySetTunnelConnected(context.Context, string) error {
	return nil
}

func (s *stubServerStore) ResumeTunnelSession(context.Context, string, string, string) (domain.Domain, domain.Tunnel, error) {
	return domain.Domain{}, domain.Tunnel{}, nil
}

func (s *stubServerStore) SetTunnelDisconnected(ctx context.Context, tunnelID string) error {
	if s.setTunnelDisconnectedFn != nil {
		return s.setTunnelDisconnectedFn(ctx, tunnelID)
	}
	return nil
}

func (s *stubServerStore) SetTunnelsDisconnected(ctx context.Context, tunnelIDs []string) error {
	if s.setTunnelsDisconnectedFn != nil {
		return s.setTunnelsDisconnectedFn(ctx, tunnelIDs)
	}
	return nil
}

func (s *stubServerStore) FindRouteByHost(ctx context.Context, host string) (domain.TunnelRoute, error) {
	if s.findRouteByHostFn != nil {
		return s.findRouteByHostFn(ctx, host)
	}
	return domain.TunnelRoute{}, nil
}

func (s *stubServerStore) FindRouteByTunnelID(context.Context, string) (domain.TunnelRoute, error) {
	return domain.TunnelRoute{}, nil
}

func (s *stubServerStore) TouchDomain(context.Context, string) error {
	return nil
}

func (s *stubServerStore) PurgeInactiveTemporaryDomains(context.Context, time.Time, int) ([]domain.Domain, error) {
	return nil, nil
}

func (s *stubServerStore) PurgeStaleConnectTokens(context.Context, time.Time, time.Time, int) (int64, error) {
	return 0, nil
}

func (s *stubServerStore) OperationalStats() sqlite.OperationalStats {
	return sqlite.OperationalStats{}
}

func (s *stubServerStore) CloseTemporaryTunnel(ctx context.Context, tunnelID string) (string, bool, error) {
	if s.closeTemporaryTunnelFn != nil {
		return s.closeTemporaryTunnelFn(ctx, tunnelID)
	}
	return "", false, nil
}

func (s *stubServerStore) ResolveAPIKeyID(context.Context, string) (string, error) {
	return "", nil
}

func TestQueueTunnelDisconnectUsesServerRuntimeContextOnImmediateFallback(t *testing.T) {
	t.Parallel()

	parentCtx, cancel := context.WithCancel(context.Background())
	cancel()

	var gotErr error
	store := &stubServerStore{
		setTunnelDisconnectedFn: func(ctx context.Context, tunnelID string) error {
			if tunnelID != "tun_1" {
				t.Fatalf("expected tunnel id tun_1, got %q", tunnelID)
			}
			gotErr = ctx.Err()
			return nil
		},
	}
	srv := &Server{
		store:         store,
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		activeTunnels: newActiveTunnelTracker(),
		disconnects:   make(chan string),
	}
	srv.runtimeCtx.Store(parentCtx)

	srv.queueTunnelDisconnect("tun_1")

	if !errors.Is(gotErr, context.Canceled) {
		t.Fatalf("expected disconnect context to inherit cancellation, got %v", gotErr)
	}
}

func TestExpireStaleSessionsUsesCallerContext(t *testing.T) {
	t.Parallel()

	parentCtx, cancel := context.WithCancel(context.Background())
	cancel()

	var gotErr error
	store := &stubServerStore{
		closeTemporaryTunnelFn: func(ctx context.Context, tunnelID string) (string, bool, error) {
			if tunnelID != "tun_stale" {
				t.Fatalf("expected stale tunnel id, got %q", tunnelID)
			}
			gotErr = ctx.Err()
			return "", false, nil
		},
	}
	idx := newLiveRouteIndex()
	idx.upsert(domain.TunnelRoute{
		Domain: domain.Domain{
			ID:       "dom_1",
			APIKeyID: "key_1",
			Hostname: "stale.example.com",
		},
		Tunnel: domain.Tunnel{
			ID:          "tun_stale",
			APIKeyID:    "key_1",
			DomainID:    "dom_1",
			State:       domain.TunnelStateConnected,
			IsTemporary: true,
		},
	})

	transport := &testTransport{}
	sess := &session{tunnelID: "tun_stale", transport: transport}
	sess.touch(time.Now().Add(-2 * time.Minute))
	if _, ok := idx.attachSession("tun_stale", sess); !ok {
		t.Fatal("expected live route index to attach session")
	}

	srv := &Server{
		cfg: config.ServerConfig{
			ClientPingTimeout: time.Second,
		},
		store:         store,
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		hub:           &hub{sessions: map[string]*session{"tun_stale": sess}},
		liveRoutes:    idx,
		activeTunnels: newActiveTunnelTracker(),
	}

	srv.expireStaleSessions(parentCtx)

	if !errors.Is(gotErr, context.Canceled) {
		t.Fatalf("expected stale-session cleanup context to inherit cancellation, got %v", gotErr)
	}
	transport.mu.Lock()
	closeCount := transport.closeCount
	transport.mu.Unlock()
	if closeCount != 1 {
		t.Fatalf("expected stale session transport to close once, got %d", closeCount)
	}
}

func TestPendingRequestsDoNotReuseBodyChannels(t *testing.T) {
	t.Parallel()

	req := acquirePendingRequest()
	bodyCh := req.ensureBodyCh()
	bodyCh <- []byte("chunk")

	req = acquirePendingRequest()
	if req.bodyCh != nil {
		t.Fatal("expected a fresh pending request without a body channel")
	}
}

func TestCertificateCleanupPreservesReassignedHostname(t *testing.T) {
	t.Parallel()

	host := "reused.example.com"
	cacheDir := t.TempDir()
	certPath := filepath.Join(cacheDir, host)
	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &stubServerStore{
		findRouteByHostFn: func(context.Context, string) (domain.TunnelRoute, error) {
			return domain.TunnelRoute{Domain: domain.Domain{ID: "new-domain", Hostname: host, Status: domain.DomainStatusActive}}, nil
		},
	}
	srv := &Server{store: store, liveRoutes: newLiveRouteIndex(), cfg: config.ServerConfig{CertCacheDir: cacheDir}}
	removed, err := srv.removeInactiveTunnelCertCache(context.Background(), host, "old-domain", true)
	if err != nil || removed != 0 {
		t.Fatalf("cleanup = (%d, %v), want no removal", removed, err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("reassigned certificate was removed: %v", err)
	}

	store.findRouteByHostFn = func(context.Context, string) (domain.TunnelRoute, error) {
		return domain.TunnelRoute{}, sql.ErrNoRows
	}
	removed, err = srv.removeInactiveTunnelCertCache(context.Background(), host, "old-domain", true)
	if err != nil || removed != 1 {
		t.Fatalf("cleanup deleted domain = (%d, %v), want one removal", removed, err)
	}
}

func TestImmediateDisconnectDoesNotOverwriteReconnect(t *testing.T) {
	t.Parallel()

	var calls int
	store := &stubServerStore{setTunnelDisconnectedFn: func(context.Context, string) error {
		calls++
		return nil
	}}
	srv := &Server{store: store, activeTunnels: newActiveTunnelTracker()}
	srv.activeTunnels.markConnected("key-1", "tunnel-1")
	srv.markTunnelDisconnectedNow(context.Background(), "tunnel-1")
	if calls != 0 {
		t.Fatalf("disconnect writes = %d, want 0 for reconnected tunnel", calls)
	}

	srv.activeTunnels.markDisconnected("tunnel-1")
	srv.markTunnelDisconnectedNow(context.Background(), "tunnel-1")
	if calls != 1 {
		t.Fatalf("disconnect writes = %d, want 1 for inactive tunnel", calls)
	}
}
