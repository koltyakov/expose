package sqlite

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestPublishedSiteVisitorsDeduplicatedAndDeletedWithSite(t *testing.T) {
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
	batch := []SiteVisitor{{site.ID, [32]byte{2}}, {site.ID, [32]byte{1}}, {site.ID, [32]byte{1}}, {"site_missing", [32]byte{9}}}
	if err := st.RecordPublishedSiteVisitors(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordPublishedSiteVisitors(ctx, []SiteVisitor{{site.ID, [32]byte{2}}}); err != nil {
		t.Fatal(err)
	}
	visitors, err := st.ListPublishedSiteVisitors(ctx, site.ID)
	if err != nil || len(visitors) != 2 || visitors[0] != [32]byte{1} || visitors[1] != [32]byte{2} {
		t.Fatalf("deduplication failed: %v, %v", visitors, err)
	}
	if missing, err := st.ListPublishedSiteVisitors(ctx, "site_missing"); err != nil || len(missing) != 0 {
		t.Fatalf("visitor stored for a missing site: %v, %v", missing, err)
	}
	if err := st.DeletePublishedSite(ctx, key.ID, site.ID); err != nil {
		t.Fatal(err)
	}
	// A late batch cannot recreate visitor data for a deleted publication.
	if err := st.RecordPublishedSiteVisitors(ctx, []SiteVisitor{{site.ID, [32]byte{4}}}); err != nil {
		t.Fatal(err)
	}
	if visitors, err := st.ListPublishedSiteVisitors(ctx, site.ID); err != nil || len(visitors) != 0 {
		t.Fatalf("deleted site retained visitors: %v, %v", visitors, err)
	}
}

func testVisitorFingerprint(site byte, i int) [32]byte {
	var fp [32]byte
	fp[0] = site
	binary.BigEndian.PutUint32(fp[1:], uint32(i))
	return fp
}

func TestPublishedSiteVisitorsCappedPerSiteInTransaction(t *testing.T) {
	st, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	key, err := st.CreateAPIKey(ctx, "owner", "visitor-cap-owner-hash")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"site_full", "site_other"} {
		site := domain.PublishedSite{ID: id, APIKeyID: key.ID, Hostname: id + ".example.com", CreatedAt: time.Now().UTC()}
		if err := st.CreatePublishedSite(ctx, site); err != nil {
			t.Fatal(err)
		}
	}
	limit := domain.PublishedSiteVisitorLimit
	batch := make([]SiteVisitor, 0, limit)
	for i := range limit - 2 {
		batch = append(batch, SiteVisitor{"site_full", testVisitorFingerprint(1, i)})
	}
	if err := st.RecordPublishedSiteVisitors(ctx, batch); err != nil {
		t.Fatal(err)
	}
	// One batch crosses the cap: duplicates take no room, the first two new
	// identities fill it, later ones are skipped, and other sites are unaffected.
	batch = []SiteVisitor{
		{"site_full", testVisitorFingerprint(1, 0)},
		{"site_full", testVisitorFingerprint(1, limit)},
		{"site_other", testVisitorFingerprint(2, 0)},
		{"site_full", testVisitorFingerprint(1, limit)},
		{"site_full", testVisitorFingerprint(1, limit+1)},
		{"site_full", testVisitorFingerprint(1, limit+2)},
		{"site_other", testVisitorFingerprint(2, 1)},
	}
	if err := st.RecordPublishedSiteVisitors(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordPublishedSiteVisitors(ctx, []SiteVisitor{{"site_full", testVisitorFingerprint(1, limit+3)}}); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM published_site_visitors WHERE site_id = 'site_full'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != limit {
		t.Fatalf("stored %d visitors, want cap %d", stored, limit)
	}
	var overflow int
	skipped, late := testVisitorFingerprint(1, limit+2), testVisitorFingerprint(1, limit+3)
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM published_site_visitors WHERE site_id = 'site_full' AND fingerprint IN (?, ?)`,
		skipped[:], late[:]).Scan(&overflow); err != nil || overflow != 0 {
		t.Fatalf("over-cap visitors stored: %d, %v", overflow, err)
	}
	if other, err := st.ListPublishedSiteVisitors(ctx, "site_other"); err != nil || len(other) != 2 {
		t.Fatalf("cap leaked across sites: %d, %v", len(other), err)
	}
}

func TestPublishedSiteVisitorsLegacyOverCapReadsBounded(t *testing.T) {
	st, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	key, err := st.CreateAPIKey(ctx, "owner", "visitor-legacy-owner-hash")
	if err != nil {
		t.Fatal(err)
	}
	site := domain.PublishedSite{ID: "site_legacy", APIKeyID: key.ID, Hostname: "legacy.example.com", CreatedAt: time.Now().UTC()}
	if err := st.CreatePublishedSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	// Older releases capped visitors only in memory; a failed lazy load could
	// let storage grow past the cap.
	limit := domain.PublishedSiteVisitorLimit
	if _, err := st.db.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
		INSERT INTO published_site_visitors(site_id, fingerprint) SELECT ?, randomblob(32) FROM n`, limit+500-1, site.ID); err != nil {
		t.Fatal(err)
	}
	visitors, err := st.ListPublishedSiteVisitors(ctx, site.ID)
	if err != nil || len(visitors) != limit {
		t.Fatalf("legacy read returned %d visitors, want %d: %v", len(visitors), limit, err)
	}
	if err := st.RecordPublishedSiteVisitors(ctx, []SiteVisitor{{site.ID, testVisitorFingerprint(9, 1)}}); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM published_site_visitors WHERE site_id = ?`, site.ID).Scan(&stored); err != nil || stored != limit+500 {
		t.Fatalf("over-cap site accepted a new visitor: %d, %v", stored, err)
	}
}
