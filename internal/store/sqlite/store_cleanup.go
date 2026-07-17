package sqlite

import (
	"context"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

const purgeInactiveTemporaryDomainsQuery = `
SELECT d.id, d.hostname
FROM domains d
WHERE d.type = 'temporary_subdomain'
	AND d.status = 'inactive'
	AND d.last_seen_at < ?
	AND NOT EXISTS (
		SELECT 1
		FROM tunnels t
		WHERE t.domain_id = d.id AND t.state = 'connected'
	)
ORDER BY d.last_seen_at ASC
LIMIT ?`

func (s *Store) PurgeInactiveTemporaryDomains(ctx context.Context, olderThan time.Time, limit int) ([]domain.Domain, error) {
	if limit <= 0 {
		limit = 100
	}

	var purged []domain.Domain
	err := s.withSerializedWrite(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		rows, err := tx.QueryContext(ctx, purgeInactiveTemporaryDomainsQuery, olderThan.UTC(), limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		type candidate struct {
			id       string
			hostname string
		}
		var candidates []candidate
		for rows.Next() {
			var c candidate
			if err = rows.Scan(&c.id, &c.hostname); err != nil {
				return err
			}
			candidates = append(candidates, c)
		}
		if err = rows.Err(); err != nil {
			return err
		}
		purged = make([]domain.Domain, 0, len(candidates))
		ids := make([]any, 0, len(candidates))
		for _, c := range candidates {
			ids = append(ids, c.id)
			purged = append(purged, domain.Domain{ID: c.id, Hostname: c.hostname})
		}

		if len(ids) > 0 {
			placeholders := strings.Repeat("?,", len(ids))
			placeholders = placeholders[:len(placeholders)-1]
			safeDomains := `SELECT d.id FROM domains d
WHERE d.id IN (` + placeholders + `)
	AND NOT EXISTS (
		SELECT 1 FROM tunnels t WHERE t.domain_id = d.id AND t.state = ?
	)`
			safeArgs := append(append([]any{}, ids...), domain.TunnelStateConnected)
			if _, err = tx.ExecContext(ctx,
				`DELETE FROM connect_tokens WHERE tunnel_id IN (SELECT id FROM tunnels WHERE domain_id IN (`+safeDomains+`))`,
				safeArgs...); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM tunnels WHERE domain_id IN (`+safeDomains+`)`, safeArgs...); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM domains WHERE id IN (`+safeDomains+`)`, safeArgs...); err != nil {
				return err
			}
		}

		return tx.Commit()
	})
	if err != nil {
		return nil, err
	}
	return purged, nil
}
