package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestReservedHostnames(t *testing.T) {
	st, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	key, err := st.CreateAPIKey(ctx, "owner", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, tunnel, err := st.AllocateDomainAndTunnel(ctx, key.ID, "permanent", "app", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	site := domain.PublishedSite{ID: "site_test", APIKeyID: key.ID, Hostname: "docs.example.com", CreatedAt: time.Now().UTC()}
	if err := st.CreatePublishedSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	st.SetReservedHostnames([]string{"APP.EXAMPLE.COM:443", "docs.example.com"})
	for _, mode := range []string{"temporary", "permanent"} {
		if _, _, err := st.AllocateDomainAndTunnel(ctx, key.ID, mode, "app", "example.com"); !errors.Is(err, ErrHostnameInUse) {
			t.Fatalf("%s allocation: %v", mode, err)
		}
	}
	if _, _, err := st.ResumeTunnelSession(ctx, tunnel.ID, key.ID, ""); !errors.Is(err, ErrHostnameInUse) {
		t.Fatalf("resume: %v", err)
	}
	if err := st.TrySetTunnelConnected(ctx, tunnel.ID); !errors.Is(err, ErrHostnameInUse) {
		t.Fatalf("connect: %v", err)
	}
	if err := st.ReplacePublishedSite(ctx, site); !errors.Is(err, ErrHostnameInUse) {
		t.Fatalf("replace publication: %v", err)
	}
	site.ID = "site_new"
	site.Hostname = "app.example.com"
	if err := st.CreatePublishedSite(ctx, site); !errors.Is(err, ErrHostnameInUse) {
		t.Fatalf("create publication: %v", err)
	}
	st.SetReservedHostnames(nil)
	if _, _, err := st.ResumeTunnelSession(ctx, tunnel.ID, key.ID, ""); err != nil {
		t.Fatalf("reservation removal: %v", err)
	}
}
