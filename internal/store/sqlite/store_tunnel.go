package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/domain"
)

// defaultTxTimeout is the fallback timeout applied to database transactions
// when the caller's context carries no deadline. This prevents transactions
// from blocking indefinitely under pathological conditions.
const defaultTxTimeout = 30 * time.Second

// txContext returns ctx unchanged when it already has a deadline, otherwise
// wraps it with defaultTxTimeout. The caller must call the returned cancel.
func txContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultTxTimeout)
}

func (s *Store) ActiveTunnelCountByKey(ctx context.Context, keyID string) (int, error) {
	var count int
	stmt := s.activeTunnelCountStmt
	if stmt == nil {
		err := s.db.QueryRowContext(ctx, activeTunnelCountByKeyQuery, keyID, domain.TunnelStateConnected).Scan(&count)
		return count, err
	}
	err := stmt.QueryRowContext(ctx, keyID, domain.TunnelStateConnected).Scan(&count)
	return count, err
}

func (s *Store) IsHostnameActive(ctx context.Context, host string) (bool, error) {
	host = normalizeHostname(host)
	var one int
	stmt := s.isHostnameActiveStmt
	var err error
	if stmt == nil {
		err = s.db.QueryRowContext(ctx, isHostnameActiveQuery, host, domain.DomainStatusActive).Scan(&one)
	} else {
		err = stmt.QueryRowContext(ctx, host, domain.DomainStatusActive).Scan(&one)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ResetConnectedTunnels(ctx context.Context) (int64, error) {
	var affected int64
	err := s.withSerializedWrite(ctx, func() error {
		txCtx, txCancel := txContext(ctx)
		defer txCancel()
		tx, err := s.db.BeginTx(txCtx, nil)
		if err != nil {
			return fmt.Errorf("begin tx (reset connected tunnels): %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		if _, err = tx.ExecContext(ctx, `
UPDATE domains
SET status = ?
WHERE id IN (
	SELECT domain_id
	FROM tunnels
	WHERE state = ? AND is_temporary = 1
)`, domain.DomainStatusInactive, domain.TunnelStateConnected); err != nil {
			return err
		}

		res, err := tx.ExecContext(ctx, `
UPDATE tunnels
SET state = ?, disconnected_at = ?
WHERE state = ?`, domain.TunnelStateDisconnected, time.Now().UTC(), domain.TunnelStateConnected)
		if err != nil {
			return err
		}
		affected, err = res.RowsAffected()
		if err != nil {
			return err
		}

		return tx.Commit()
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func (s *Store) AllocateDomainAndTunnel(ctx context.Context, keyID, mode, subdomain, baseDomain string) (domain.Domain, domain.Tunnel, error) {
	return s.AllocateDomainAndTunnelWithClientMeta(ctx, keyID, mode, subdomain, baseDomain, "")
}

func (s *Store) AllocateDomainAndTunnelWithClientMeta(ctx context.Context, keyID, mode, subdomain, baseDomain, clientMeta string) (domain.Domain, domain.Tunnel, error) {
	in, err := s.buildAllocationInput(ctx, mode, subdomain, baseDomain, clientMeta)
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}

	var (
		d domain.Domain
		t domain.Tunnel
	)
	err = s.withSerializedWrite(ctx, func() error {
		txCtx, txCancel := txContext(ctx)
		defer txCancel()
		tx, err := s.db.BeginTx(txCtx, nil)
		if err != nil {
			return fmt.Errorf("begin tx (allocate domain/tunnel): %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		now := time.Now().UTC()
		d, err = s.claimOrCreateDomainTx(ctx, tx, keyID, in, now)
		if err != nil {
			return err
		}
		t, err = insertAllocatedTunnelTx(ctx, tx, keyID, d.ID, in.isTemporary, in.clientMeta)
		if err != nil {
			return err
		}

		return tx.Commit()
	})
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	return d, t, nil
}

func (s *Store) ResumeTunnelSession(ctx context.Context, tunnelID, keyID, clientMeta string) (domain.Domain, domain.Tunnel, error) {
	clientMeta = strings.TrimSpace(clientMeta)
	var (
		d domain.Domain
		t domain.Tunnel
	)
	err := s.withSerializedWrite(ctx, func() error {
		txCtx, txCancel := txContext(ctx)
		defer txCancel()
		tx, err := s.db.BeginTx(txCtx, nil)
		if err != nil {
			return fmt.Errorf("begin tx (resume tunnel session): %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		var lastSeen sql.NullTime
		var connectedAt sql.NullTime
		var disconnectedAt sql.NullTime
		var storedClientMeta sql.NullString
		var accessUser sql.NullString
		var accessMode sql.NullString
		var accessPasswordHash sql.NullString
		if err = tx.QueryRowContext(ctx, `
SELECT
 d.id, d.api_key_id, d.type, d.hostname, d.status, d.created_at, d.last_seen_at,
 t.id, t.api_key_id, t.domain_id, t.state, t.is_temporary, t.client_meta, t.access_user, t.access_mode, t.access_password_hash, t.connected_at, t.disconnected_at
FROM tunnels t
JOIN domains d ON d.id = t.domain_id
WHERE t.id = ?`, tunnelID).Scan(
			&d.ID, &d.APIKeyID, &d.Type, &d.Hostname, &d.Status, &d.CreatedAt, &lastSeen,
			&t.ID, &t.APIKeyID, &t.DomainID, &t.State, &t.IsTemporary, &storedClientMeta, &accessUser, &accessMode, &accessPasswordHash, &connectedAt, &disconnectedAt,
		); err != nil {
			return err
		}
		if d.APIKeyID != keyID || t.APIKeyID != keyID {
			return ErrHostnameInUse
		}
		if t.State == domain.TunnelStateClosed {
			return sql.ErrNoRows
		}
		if storedClientMeta.Valid {
			t.ClientMeta = storedClientMeta.String
		}
		if accessUser.Valid {
			t.AccessUser = accessUser.String
		}
		if accessMode.Valid {
			t.AccessMode = accessMode.String
		}
		if accessPasswordHash.Valid {
			t.AccessPasswordHash = accessPasswordHash.String
		}
		if connectedAt.Valid {
			v := connectedAt.Time
			t.ConnectedAt = &v
		}
		if disconnectedAt.Valid {
			v := disconnectedAt.Time
			t.DisconnectedAt = &v
		}
		if lastSeen.Valid {
			v := lastSeen.Time
			d.LastSeenAt = &v
		}
		if existing := strings.TrimSpace(t.ClientMeta); existing != "" && clientMeta != "" && existing != clientMeta {
			return ErrHostnameInUse
		}

		if _, err = tx.ExecContext(ctx, `
UPDATE domains
SET status = ?
WHERE id = ?`, domain.DomainStatusActive, d.ID); err != nil {
			return err
		}
		d.Status = domain.DomainStatusActive
		if clientMeta != "" && clientMeta != strings.TrimSpace(t.ClientMeta) {
			if _, err = tx.ExecContext(ctx, `
UPDATE tunnels
SET client_meta = ?
WHERE id = ?`, nullableString(clientMeta), t.ID); err != nil {
				return err
			}
			t.ClientMeta = clientMeta
		}
		return tx.Commit()
	})
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	return d, t, nil
}

func (s *Store) SetTunnelConnected(ctx context.Context, tunnelID string) error {
	_, err := s.execWithSQLiteBusyRetry(ctx, `
UPDATE tunnels
SET state = ?, connected_at = ?, disconnected_at = NULL
WHERE id = ?`,
		domain.TunnelStateConnected, time.Now().UTC(), tunnelID)
	return err
}

func (s *Store) TrySetTunnelConnected(ctx context.Context, tunnelID string) error {
	return s.withSerializedWrite(ctx, func() error {
		txCtx, txCancel := txContext(ctx)
		defer txCancel()
		tx, err := s.db.BeginTx(txCtx, nil)
		if err != nil {
			return fmt.Errorf("begin tx (try set tunnel connected): %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		var keyID string
		var state string
		if err = tx.QueryRowContext(ctx, `SELECT api_key_id, state FROM tunnels WHERE id = ?`, tunnelID).Scan(&keyID, &state); err != nil {
			return err
		}
		if state == domain.TunnelStateConnected {
			return tx.Commit()
		}

		var limit int
		if err = tx.QueryRowContext(ctx, `SELECT tunnel_limit FROM api_keys WHERE id = ?`, keyID).Scan(&limit); err != nil {
			return err
		}
		if limit >= 0 {
			var active int
			if err = tx.QueryRowContext(ctx, `
SELECT COUNT(1)
FROM tunnels
WHERE api_key_id = ? AND state = ?`, keyID, domain.TunnelStateConnected).Scan(&active); err != nil {
				return err
			}
			if active >= limit {
				return domain.ErrTunnelLimitReached
			}
		}

		if _, err = tx.ExecContext(ctx, `
UPDATE tunnels
SET state = ?, connected_at = ?, disconnected_at = NULL
WHERE id = ?`,
			domain.TunnelStateConnected, time.Now().UTC(), tunnelID); err != nil {
			return err
		}

		return tx.Commit()
	})
}

func (s *Store) SetTunnelAccessCredentials(ctx context.Context, tunnelID, user, mode, hash string) error {
	_, err := s.execWithSQLiteBusyRetry(ctx, `UPDATE tunnels SET access_user = ?, access_mode = ?, access_password_hash = ? WHERE id = ?`, nullableString(user), nullableString(mode), nullableString(hash), tunnelID)
	return err
}

func (s *Store) SetTunnelAccessPasswordHash(ctx context.Context, tunnelID, hash string) error {
	_, err := s.execWithSQLiteBusyRetry(ctx, `UPDATE tunnels SET access_user = ?, access_mode = ?, access_password_hash = ? WHERE id = ?`, "admin", access.ModeBasic, nullableString(hash), tunnelID)
	return err
}

func (s *Store) SetTunnelDisconnected(ctx context.Context, tunnelID string) error {
	return s.withSerializedWrite(ctx, func() error {
		txCtx, txCancel := txContext(ctx)
		defer txCancel()
		tx, err := s.db.BeginTx(txCtx, nil)
		if err != nil {
			return fmt.Errorf("begin tx (set tunnel disconnected): %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		var state string
		var isTemp bool
		var domainID string
		if err = tx.QueryRowContext(ctx, `SELECT state, is_temporary, domain_id FROM tunnels WHERE id = ?`, tunnelID).Scan(&state, &isTemp, &domainID); err != nil {
			return err
		}
		if state == domain.TunnelStateClosed {
			return tx.Commit()
		}

		if _, err = tx.ExecContext(ctx, `UPDATE tunnels SET state = ?, disconnected_at = ? WHERE id = ?`, domain.TunnelStateDisconnected, time.Now().UTC(), tunnelID); err != nil {
			return err
		}

		if isTemp {
			if _, err = tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusInactive, domainID); err != nil {
				return err
			}
		}
		return tx.Commit()
	})
}

func (s *Store) SetTunnelsDisconnected(ctx context.Context, tunnelIDs []string) error {
	ids := uniqueTunnelIDs(tunnelIDs)
	if len(ids) == 0 {
		return nil
	}

	return s.withSerializedWrite(ctx, func() error {
		txCtx, txCancel := txContext(ctx)
		defer txCancel()
		tx, err := s.db.BeginTx(txCtx, nil)
		if err != nil {
			return fmt.Errorf("begin tx (set tunnels disconnected): %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		placeholders := strings.Repeat("?,", len(ids))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]any, 0, len(ids))
		for _, id := range ids {
			args = append(args, id)
		}

		rows, err := tx.QueryContext(ctx,
			`SELECT id, state, is_temporary, domain_id FROM tunnels WHERE id IN (`+placeholders+`)`,
			args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		activeIDs := make([]string, 0, len(ids))
		tempDomainIDs := make(map[string]struct{}, len(ids))
		for rows.Next() {
			var (
				id       string
				state    string
				isTemp   bool
				domainID string
			)
			if err = rows.Scan(&id, &state, &isTemp, &domainID); err != nil {
				return err
			}
			if state == domain.TunnelStateClosed {
				continue
			}
			activeIDs = append(activeIDs, id)
			if isTemp && strings.TrimSpace(domainID) != "" {
				tempDomainIDs[domainID] = struct{}{}
			}
		}
		if err = rows.Err(); err != nil {
			return err
		}
		if len(activeIDs) == 0 {
			return tx.Commit()
		}

		activePlaceholders := strings.Repeat("?,", len(activeIDs))
		activePlaceholders = activePlaceholders[:len(activePlaceholders)-1]
		updateArgs := make([]any, 0, 3+len(activeIDs))
		updateArgs = append(updateArgs, domain.TunnelStateDisconnected, time.Now().UTC())
		for _, id := range activeIDs {
			updateArgs = append(updateArgs, id)
		}
		updateArgs = append(updateArgs, domain.TunnelStateClosed)

		if _, err = tx.ExecContext(ctx,
			`UPDATE tunnels SET state = ?, disconnected_at = ? WHERE id IN (`+activePlaceholders+`) AND state != ?`,
			updateArgs...); err != nil {
			return err
		}

		if len(tempDomainIDs) > 0 {
			domainIDs := make([]string, 0, len(tempDomainIDs))
			for domainID := range tempDomainIDs {
				domainIDs = append(domainIDs, domainID)
			}

			domainPlaceholders := strings.Repeat("?,", len(domainIDs))
			domainPlaceholders = domainPlaceholders[:len(domainPlaceholders)-1]
			domainArgs := make([]any, 0, 1+len(domainIDs))
			domainArgs = append(domainArgs, domain.DomainStatusInactive)
			for _, domainID := range domainIDs {
				domainArgs = append(domainArgs, domainID)
			}
			if _, err = tx.ExecContext(ctx,
				`UPDATE domains SET status = ? WHERE id IN (`+domainPlaceholders+`)`,
				domainArgs...); err != nil {
				return err
			}
		}

		return tx.Commit()
	})
}

func (s *Store) CloseTemporaryTunnel(ctx context.Context, tunnelID string) (string, bool, error) {
	var (
		hostname string
		closed   bool
	)
	err := s.withSerializedWrite(ctx, func() error {
		txCtx, txCancel := txContext(ctx)
		defer txCancel()
		tx, err := s.db.BeginTx(txCtx, nil)
		if err != nil {
			return fmt.Errorf("begin tx (close temporary tunnel): %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		var state string
		var isTemp bool
		var domainID string
		var domainType string
		if err = tx.QueryRowContext(ctx, `
SELECT t.state, t.is_temporary, t.domain_id, d.type, d.hostname
FROM tunnels t
JOIN domains d ON d.id = t.domain_id
WHERE t.id = ?`, tunnelID).Scan(&state, &isTemp, &domainID, &domainType, &hostname); err != nil {
			return err
		}

		if !isTemp || domainType != domain.DomainTypeTemporarySubdomain {
			hostname = ""
			closed = false
			return tx.Commit()
		}
		if state == domain.TunnelStateClosed {
			closed = false
			return tx.Commit()
		}

		now := time.Now().UTC()
		if _, err = tx.ExecContext(ctx, `UPDATE tunnels SET state = ?, disconnected_at = ? WHERE id = ?`, domain.TunnelStateClosed, now, tunnelID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusInactive, domainID); err != nil {
			return err
		}

		closed = true
		return tx.Commit()
	})
	if err != nil {
		return "", false, err
	}
	return hostname, closed, nil
}

func uniqueTunnelIDs(tunnelIDs []string) []string {
	if len(tunnelIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tunnelIDs))
	out := make([]string, 0, len(tunnelIDs))
	for _, id := range tunnelIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
