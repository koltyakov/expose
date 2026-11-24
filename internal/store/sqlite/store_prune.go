package sqlite

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

// pruneClosedTunnelsQuery selects closed tunnel rows nothing reads any more:
// closed before the cutoff, not the newest tunnel of their domain (routes,
// exposures and reconnects use that one), and holding no unexpired connect
// token (those still count as registration reservations).
const pruneClosedTunnelsQuery = `
SELECT t.id
FROM tunnels t
WHERE t.state = ?
	AND COALESCE(t.disconnected_at, t.connected_at) < ?
	AND t.id != (
		SELECT newest.id FROM tunnels newest
		WHERE newest.domain_id = t.domain_id
		ORDER BY newest.connected_at DESC, newest.id DESC
		LIMIT 1
	)
	AND NOT EXISTS (
		SELECT 1 FROM connect_tokens ct
		WHERE ct.tunnel_id = t.id AND ct.expires_at >= ?
	)
LIMIT ?`

// PruneClosedTunnels deletes up to limit closed tunnel rows, and their
// connect tokens, that were closed before olderThan. Every registration adds
// a row, so without pruning the per-key reservation count and domain lookups
// scan an ever-growing history.
func (s *Store) PruneClosedTunnels(ctx context.Context, olderThan, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}
	pruned := 0
	err := s.withSerializedWrite(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		rows, err := tx.QueryContext(ctx, pruneClosedTunnelsQuery, domain.TunnelStateClosed, olderThan.UTC(), now.UTC(), limit)
		if err != nil {
			return err
		}
		var ids []any
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		if _, err := tx.ExecContext(ctx, `DELETE FROM connect_tokens WHERE tunnel_id IN (`+placeholders+`)`, ids...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tunnels WHERE id IN (`+placeholders+`)`, ids...); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		pruned = len(ids)
		return nil
	})
	return pruned, err
}
