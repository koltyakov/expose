package sqlite

import (
	"context"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func (s *Store) PurgeInactiveTemporaryDomains(ctx context.Context, olderThan time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
SELECT
	d.id,
	d.hostname
FROM domains d
LEFT JOIN tunnels t ON t.domain_id = d.id
WHERE d.type = ? AND d.status = ?
GROUP BY d.id, d.hostname, d.created_at, d.last_seen_at
HAVING COALESCE(MAX(t.disconnected_at), MAX(t.connected_at), d.last_seen_at, d.created_at) < ?
ORDER BY COALESCE(MAX(t.disconnected_at), MAX(t.connected_at), d.last_seen_at, d.created_at) ASC
LIMIT ?`,
		domain.DomainTypeTemporarySubdomain, domain.DomainStatusInactive, olderThan.UTC(), limit)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		candidates = append(candidates, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	hosts := make([]string, 0, len(candidates))
	ids := make([]any, 0, len(candidates))
	for _, c := range candidates {
		ids = append(ids, c.id)
		hosts = append(hosts, c.hostname)
	}

	if len(ids) > 0 {
		placeholders := strings.Repeat("?,", len(ids))
		placeholders = placeholders[:len(placeholders)-1]
		if _, err = tx.ExecContext(ctx,
			`DELETE FROM connect_tokens WHERE tunnel_id IN (SELECT id FROM tunnels WHERE domain_id IN (`+placeholders+`))`,
			ids...); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM tunnels WHERE domain_id IN (`+placeholders+`)`, ids...); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM domains WHERE id IN (`+placeholders+`)`, ids...); err != nil {
			return nil, err
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return hosts, nil
}
