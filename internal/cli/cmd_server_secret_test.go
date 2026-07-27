package cli

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/koltyakov/expose/internal/store/sqlite"
)

func openSecretTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "secrets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestResolveAccessCookieSecretConfiguredWins(t *testing.T) {
	store := openSecretTestStore(t)
	ctx := context.Background()

	secret, ephemeral, err := resolveAccessCookieSecret(ctx, store, "  configured-secret  ")
	if err != nil {
		t.Fatal(err)
	}
	if ephemeral {
		t.Fatal("configured secret must not be flagged ephemeral")
	}
	if secret != "configured-secret" {
		t.Fatalf("expected configured secret to win, got %q", secret)
	}
	if _, exists, err := store.GetAccessCookieSecret(ctx); err != nil || exists {
		t.Fatalf("configured secret must not be persisted, got exists=%v err=%v", exists, err)
	}
}

func TestResolveAccessCookieSecretGeneratesAndPersists(t *testing.T) {
	store := openSecretTestStore(t)
	ctx := context.Background()

	secret, ephemeral, err := resolveAccessCookieSecret(ctx, store, "")
	if err != nil {
		t.Fatal(err)
	}
	if ephemeral {
		t.Fatal("persisted secret must not be flagged ephemeral")
	}
	if secret == "" {
		t.Fatal("expected a generated secret")
	}

	stored, exists, err := store.GetAccessCookieSecret(ctx)
	if err != nil || !exists {
		t.Fatalf("expected persisted secret, got exists=%v err=%v", exists, err)
	}
	if stored != secret {
		t.Fatalf("persisted secret %q does not match returned %q", stored, secret)
	}

	again, ephemeral, err := resolveAccessCookieSecret(ctx, store, "")
	if err != nil {
		t.Fatal(err)
	}
	if ephemeral || again != secret {
		t.Fatalf("expected stable persisted secret, got %q ephemeral=%v", again, ephemeral)
	}
}

func TestResolveAccessCookieSecretReusesExistingPersisted(t *testing.T) {
	store := openSecretTestStore(t)
	ctx := context.Background()

	if _, err := store.ResolveAccessCookieSecret(ctx, "pre-seeded"); err != nil {
		t.Fatal(err)
	}
	secret, ephemeral, err := resolveAccessCookieSecret(ctx, store, "")
	if err != nil {
		t.Fatal(err)
	}
	if ephemeral || secret != "pre-seeded" {
		t.Fatalf("expected pre-seeded secret, got %q ephemeral=%v", secret, ephemeral)
	}
}

func TestResolveAccessCookieSecretConcurrentFirstUse(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent.db")
	first, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()

	stores := []*sqlite.Store{first, second}
	secrets := make([]string, len(stores))
	errs := make([]error, len(stores))
	var wg sync.WaitGroup
	for i, store := range stores {
		wg.Go(func() {
			secrets[i], errs[i] = store.ResolveAccessCookieSecret(context.Background(), "candidate-"+string(rune('a'+i)))
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if secrets[0] == "" || secrets[0] != secrets[1] {
		t.Fatalf("concurrent resolvers returned different secrets: %q and %q", secrets[0], secrets[1])
	}
}

func TestResolveAccessCookieSecretEphemeralOnDBFailure(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	secret, ephemeral, err := resolveAccessCookieSecret(context.Background(), store, "")
	if err != nil {
		t.Fatal(err)
	}
	if !ephemeral {
		t.Fatal("expected ephemeral fallback when the database is unavailable")
	}
	if secret == "" {
		t.Fatal("expected an ephemeral random secret")
	}
}

func TestResolveServerPepperGeneratesRandomWhenUnset(t *testing.T) {
	ctx := context.Background()

	first := openSecretTestStore(t)
	pepper1, err := resolveServerPepper(ctx, first, "")
	if err != nil {
		t.Fatal(err)
	}
	if pepper1 == "" {
		t.Fatal("expected a generated pepper")
	}

	again, err := resolveServerPepper(ctx, first, "")
	if err != nil {
		t.Fatal(err)
	}
	if again != pepper1 {
		t.Fatal("expected the persisted pepper to be stable across starts")
	}

	// Two independent deployments must not converge on the same pepper (the
	// old machine-id derivation produced identical values on one host).
	second := openSecretTestStore(t)
	pepper2, err := resolveServerPepper(ctx, second, "")
	if err != nil {
		t.Fatal(err)
	}
	if pepper2 == pepper1 {
		t.Fatal("expected distinct peppers across independent databases")
	}
}

func TestResolveServerPepperConfiguredPersistsAndMismatchFails(t *testing.T) {
	store := openSecretTestStore(t)
	ctx := context.Background()

	pepper, err := resolveServerPepper(ctx, store, "explicit-pepper")
	if err != nil {
		t.Fatal(err)
	}
	if pepper != "explicit-pepper" {
		t.Fatalf("expected explicit pepper, got %q", pepper)
	}
	if _, err := resolveServerPepper(ctx, store, "other-pepper"); err == nil {
		t.Fatal("expected mismatch with persisted pepper to fail")
	}
}
