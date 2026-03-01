package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

const getAPIKeyTunnelLimitQuery = `SELECT tunnel_limit FROM api_keys WHERE id = ?`

func (s *Store) CreateAPIKey(ctx context.Context, name, keyHash string) (domain.APIKey, error) {
	return s.CreateAPIKeyWithLimit(ctx, name, keyHash, -1)
}

func (s *Store) CreateAPIKeyWithLimit(ctx context.Context, name, keyHash string, tunnelLimit int) (domain.APIKey, error) {
	now := time.Now().UTC()
	id, err := newID("k")
	if err != nil {
		return domain.APIKey{}, err
	}
	k := domain.APIKey{
		ID:          id,
		Name:        name,
		KeyHash:     keyHash,
		CreatedAt:   now,
		TunnelLimit: tunnelLimit,
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO api_keys(id, name, key_hash, created_at, revoked_at, tunnel_limit)
VALUES(?, ?, ?, ?, NULL, ?)`, k.ID, k.Name, k.KeyHash, k.CreatedAt, k.TunnelLimit)
	return k, err
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, key_hash, created_at, revoked_at, tunnel_limit
FROM api_keys
ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []domain.APIKey
	for rows.Next() {
		var k domain.APIKey
		var revoked sql.NullTime
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.CreatedAt, &revoked, &k.TunnelLimit); err != nil {
			return nil, err
		}
		if revoked.Valid {
			t := revoked.Time
			k.RevokedAt = &t
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ResolveAPIKeyID(ctx context.Context, keyHash string) (string, error) {
	var id string
	stmt := s.resolveAPIKeyIDStmt
	if stmt == nil {
		err := s.db.QueryRowContext(ctx, resolveAPIKeyIDQuery, keyHash).Scan(&id)
		return id, err
	}
	err := stmt.QueryRowContext(ctx, keyHash).Scan(&id)
	return id, err
}

// GetAPIKeyTunnelLimit returns the per-key tunnel limit for the given key ID.
// A value of -1 means unlimited.
func (s *Store) GetAPIKeyTunnelLimit(ctx context.Context, keyID string) (int, error) {
	var limit int
	stmt := s.getAPIKeyTunnelLimitStmt
	if stmt == nil {
		err := s.db.QueryRowContext(ctx, getAPIKeyTunnelLimitQuery, keyID).Scan(&limit)
		return limit, err
	}
	err := stmt.QueryRowContext(ctx, keyID).Scan(&limit)
	return limit, err
}

// SetAPIKeyTunnelLimit updates the per-key tunnel limit. Use -1 for unlimited.
func (s *Store) SetAPIKeyTunnelLimit(ctx context.Context, keyID string, limit int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET tunnel_limit = ? WHERE id = ?`, limit, keyID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) GetServerPepper(ctx context.Context) (string, bool, error) {
	var current string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key = 'api_key_pepper'`).Scan(&current)
	if err == nil {
		return current, true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return "", false, err
}

func (s *Store) ResolveServerPepper(ctx context.Context, suggested string) (string, error) {
	suggested = strings.TrimSpace(suggested)

	var current string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM server_settings WHERE key = 'api_key_pepper'`).Scan(&current)
	if err == nil {
		if suggested != "" && suggested != current {
			return "", errors.New("provided api key pepper does not match database")
		}
		return current, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO server_settings(key, value) VALUES('api_key_pepper', ?)`, suggested); err != nil {
		return "", err
	}
	return suggested, nil
}
