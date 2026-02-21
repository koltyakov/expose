package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) CreateConnectToken(ctx context.Context, tunnelID string, ttl time.Duration) (string, error) {
	token, err := newID("ct")
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO connect_tokens(token, tunnel_id, expires_at, used_at)
VALUES(?, ?, ?, NULL)`, token, tunnelID, time.Now().UTC().Add(ttl))
	return token, err
}

func (s *Store) ConsumeConnectToken(ctx context.Context, token string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var tunnelID string
	var expires time.Time
	var used sql.NullTime
	if err = tx.QueryRowContext(ctx, `
SELECT tunnel_id, expires_at, used_at
FROM connect_tokens
WHERE token = ?`, token).Scan(&tunnelID, &expires, &used); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if used.Valid {
		return "", errors.New("token already used")
	}
	if now.After(expires) {
		return "", errors.New("token expired")
	}

	res, err := tx.ExecContext(ctx, `
UPDATE connect_tokens
SET used_at = ?
WHERE token = ? AND used_at IS NULL AND expires_at >= ?`, now, token, now)
	if err != nil {
		return "", err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", errors.New("token already used")
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return tunnelID, nil
}

// PurgeStaleConnectTokens removes expired tokens and used tokens older than the
// provided cutoff. It limits each run to avoid long write transactions.
func (s *Store) PurgeStaleConnectTokens(ctx context.Context, now, usedOlderThan time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = defaultConnectTokenPurgeLimit
	}
	now = now.UTC()
	usedOlderThan = usedOlderThan.UTC()

	res, err := s.db.ExecContext(ctx, `
DELETE FROM connect_tokens
WHERE token IN (
	SELECT token
	FROM connect_tokens
	WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)
	ORDER BY COALESCE(used_at, expires_at) ASC
	LIMIT ?
)`, now, usedOlderThan, limit)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affected, nil
}
