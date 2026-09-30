package sqlite

import "context"

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

func (s *Store) RecordPublishedSiteVisitor(ctx context.Context, siteID string, fingerprint [32]byte, limit int) error {
	return s.withSerializedWrite(ctx, func() error {
		_, err := s.db.ExecContext(ctx, `INSERT INTO published_site_visitors(site_id, fingerprint)
			SELECT ?, ? WHERE EXISTS (SELECT 1 FROM published_sites WHERE id = ?)
			AND (SELECT COUNT(*) FROM published_site_visitors WHERE site_id = ?) < ?
			ON CONFLICT DO NOTHING`, siteID, fingerprint[:], siteID, siteID, limit)
		return err
	})
}
