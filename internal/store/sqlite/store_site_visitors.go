package sqlite

import (
	"context"
	"fmt"

	"github.com/koltyakov/expose/internal/domain"
)

// SiteVisitor is one visitor fingerprint for a published site.
type SiteVisitor struct {
	SiteID      string
	Fingerprint [32]byte
}

// ListPublishedSiteVisitors returns at most domain.PublishedSiteVisitorLimit
// fingerprints for the site. Visitor identities belong to the stable
// publication ID, not its content revision. Rows beyond the cap, written by
// releases that did not enforce it in storage, are never read.
func (s *Store) ListPublishedSiteVisitors(ctx context.Context, siteID string) ([][32]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT fingerprint FROM published_site_visitors
		WHERE site_id = ? ORDER BY fingerprint LIMIT ?`, siteID, domain.PublishedSiteVisitorLimit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var visitors [][32]byte
	for rows.Next() {
		var fingerprint []byte
		if err := rows.Scan(&fingerprint); err != nil {
			return nil, err
		}
		if len(fingerprint) != 32 {
			return nil, fmt.Errorf("published site visitor fingerprint has %d bytes", len(fingerprint))
		}
		visitors = append(visitors, [32]byte(fingerprint))
	}
	return visitors, rows.Err()
}

// RecordPublishedSiteVisitors stores visitor fingerprints in one transaction.
// Rows for deleted sites are skipped. Each site keeps at most
// domain.PublishedSiteVisitorLimit rows: the transaction counts a site's
// stored rows once (bounded by the cap) and skips new identities once it is
// full, so the cap holds even when the server's in-memory set was not loaded
// from storage first. Skipped rows are not an error.
func (s *Store) RecordPublishedSiteVisitors(ctx context.Context, visitors []SiteVisitor) error {
	if len(visitors) == 0 {
		return nil
	}
	return s.withSerializedWrite(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		count, err := tx.PrepareContext(ctx, `SELECT COUNT(*) FROM (
			SELECT 1 FROM published_site_visitors WHERE site_id = ? LIMIT ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = count.Close() }()
		insert, err := tx.PrepareContext(ctx, `INSERT INTO published_site_visitors(site_id, fingerprint)
			SELECT ?, ? WHERE EXISTS (SELECT 1 FROM published_sites WHERE id = ?)
			ON CONFLICT DO NOTHING`)
		if err != nil {
			return err
		}
		defer func() { _ = insert.Close() }()
		room := make(map[string]int, 1)
		for _, v := range visitors {
			left, counted := room[v.SiteID]
			if !counted {
				var stored int
				if err := count.QueryRowContext(ctx, v.SiteID, domain.PublishedSiteVisitorLimit).Scan(&stored); err != nil {
					return err
				}
				left = max(domain.PublishedSiteVisitorLimit-stored, 0)
			}
			if left > 0 {
				res, err := insert.ExecContext(ctx, v.SiteID, v.Fingerprint[:], v.SiteID)
				if err != nil {
					return err
				}
				added, err := res.RowsAffected()
				if err != nil {
					return err
				}
				left -= int(added)
			}
			room[v.SiteID] = left
		}
		return tx.Commit()
	})
}
