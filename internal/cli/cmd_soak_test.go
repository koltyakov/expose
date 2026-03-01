package cli

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/config"
)

type fakeSoakClient struct {
	run  func(context.Context, client.LifecycleHooks) error
	hook client.LifecycleHooks
}

func (f *fakeSoakClient) SetVersion(string)                         {}
func (f *fakeSoakClient) SetLogger(*slog.Logger)                    {}
func (f *fakeSoakClient) SetLifecycleHooks(h client.LifecycleHooks) { f.hook = h }
func (f *fakeSoakClient) Run(ctx context.Context) error {
	if f.run == nil {
		<-ctx.Done()
		return nil
	}
	return f.run(ctx, f.hook)
}

func TestNormalizeSoakPrefix(t *testing.T) {
	t.Parallel()

	if got := normalizeSoakPrefix("  PG Sync__Soak!!  "); got != "pg-sync-soak" {
		t.Fatalf("expected normalized soak prefix, got %q", got)
	}
	if got := normalizeSoakPrefix("___"); got != "soak" {
		t.Fatalf("expected fallback soak prefix, got %q", got)
	}
}

func TestSoakRunnerTracksReadyWorkers(t *testing.T) {
	t.Parallel()

	factory := func(cfg config.ClientConfig) soakClient {
		return &fakeSoakClient{
			run: func(ctx context.Context, hooks client.LifecycleHooks) error {
				if hooks.OnTunnelReady != nil {
					hooks.OnTunnelReady(client.TunnelReadyEvent{TunnelID: cfg.Name})
				}
				<-ctx.Done()
				return nil
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	var out bytes.Buffer
	runner := soakRunner{
		ctx:            ctx,
		version:        "test",
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		clientLog:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		out:            &out,
		baseCfg:        config.ClientConfig{LocalPort: 3000, RegistrationMode: "temporary"},
		workers:        []*soakWorkerState{{name: "soak-0001"}, {name: "soak-0002"}, {name: "soak-0003"}},
		reportInterval: time.Hour,
		newClient:      factory,
	}

	snap := runner.run(0)
	if snap.PeakActive != 3 {
		t.Fatalf("expected peak active 3, got %d", snap.PeakActive)
	}
	if snap.ReadyEvents != 3 {
		t.Fatalf("expected 3 ready events, got %d", snap.ReadyEvents)
	}
	if snap.CurrentActive != 0 {
		t.Fatalf("expected active workers to be 0 after shutdown, got %d", snap.CurrentActive)
	}
}

func TestSoakRunnerTracksChurnRestarts(t *testing.T) {
	t.Parallel()

	factory := func(cfg config.ClientConfig) soakClient {
		return &fakeSoakClient{
			run: func(ctx context.Context, hooks client.LifecycleHooks) error {
				if hooks.OnTunnelReady != nil {
					hooks.OnTunnelReady(client.TunnelReadyEvent{TunnelID: cfg.Name})
				}
				<-ctx.Done()
				return nil
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	runner := soakRunner{
		ctx:            ctx,
		version:        "test",
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		clientLog:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		out:            io.Discard,
		baseCfg:        config.ClientConfig{LocalPort: 3000, RegistrationMode: "temporary"},
		workers:        []*soakWorkerState{{name: "soak-0001"}, {name: "soak-0002"}},
		reportInterval: time.Hour,
		churnInterval:  20 * time.Millisecond,
		churnBatch:     1,
		newClient:      factory,
	}

	snap := runner.run(0)
	if snap.ChurnRestarts == 0 {
		t.Fatal("expected churn restarts to be recorded")
	}
	if snap.PeakActive == 0 {
		t.Fatal("expected at least one active worker during churn run")
	}
}
