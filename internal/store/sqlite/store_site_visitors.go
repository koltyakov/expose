package sqlite

import "context"

// SiteVisitor is one visitor fingerprint for a published site.
type SiteVisitor struct {
	SiteID      string
	Fingerprint [32]byte
}

// Visitor identities belong to the stable publication ID, not its content revision.
func (s *Store) ListPublishedSiteVisitors(ctx context.Context, siteID string) ([][32]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT fingerprint FROM published_site_visitors WHERE site_id = ? ORDER BY fingerprint`, siteID)
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
		visitors = append(visitors, [32]byte(fingerprint))
	}
	return visitors, rows.Err()
}

// RecordPublishedSiteVisitors stores visitor fingerprints in one transaction.
// Rows for deleted sites are skipped. The per-site cap is enforced by the
// server's in-memory visitor set, which is loaded from this table, so the
// insert does not count existing rows.
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
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO published_site_visitors(site_id, fingerprint)
			SELECT ?, ? WHERE EXISTS (SELECT 1 FROM published_sites WHERE id = ?)
			ON CONFLICT DO NOTHING`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, v := range visitors {
			if _, err := stmt.ExecContext(ctx, v.SiteID, v.Fingerprint[:], v.SiteID); err != nil {
				return err
			}
		}
		return tx.Commit()
	})
}
