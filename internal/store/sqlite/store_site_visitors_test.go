package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestPublishedSiteVisitorsBoundedAndDeletedWithSite(t *testing.T) {
	st, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	key, err := st.CreateAPIKey(ctx, "owner", "visitor-owner-hash")
	if err != nil {
		t.Fatal(err)
	}
	site := domain.PublishedSite{ID: "site_visitors", APIKeyID: key.ID, Hostname: "visitors.example.com", CreatedAt: time.Now().UTC()}
	if err := st.CreatePublishedSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	for _, fingerprint := range [][32]byte{{1}, {1}, {2}, {3}} {
		if err := st.RecordPublishedSiteVisitor(ctx, site.ID, fingerprint, 2); err != nil {
			t.Fatal(err)
		}
	}
	visitors, err := st.ListPublishedSiteVisitors(ctx, site.ID)
	if err != nil || len(visitors) != 2 || visitors[0] != [32]byte{1} || visitors[1] != [32]byte{2} {
		t.Fatalf("deduplication or cap failed: %v, %v", visitors, err)
	}
	if err := st.DeletePublishedSite(ctx, key.ID, site.ID); err != nil {
		t.Fatal(err)
	}
	// A late request cannot recreate visitor data for a deleted publication.
	if err := st.RecordPublishedSiteVisitor(ctx, site.ID, [32]byte{4}, 2); err != nil {
		t.Fatal(err)
	}
	if visitors, err := st.ListPublishedSiteVisitors(ctx, site.ID); err != nil || len(visitors) != 0 {
		t.Fatalf("deleted site retained visitors: %v, %v", visitors, err)
	}
}
