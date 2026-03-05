package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/domain"
)

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
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
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
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
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

func (s *Store) SwapTunnelSession(ctx context.Context, domainID, keyID, clientMeta string) (domain.Tunnel, error) {
	clientMeta = strings.TrimSpace(clientMeta)
	var t domain.Tunnel
	err := s.withSerializedWrite(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()

		var apiKeyID string
		var domainType string
		if err = tx.QueryRowContext(ctx, `
SELECT api_key_id, type
FROM domains
WHERE id = ?`, domainID).Scan(&apiKeyID, &domainType); err != nil {
			return err
		}
		if apiKeyID != keyID {
			return ErrHostnameInUse
		}

		now := time.Now().UTC()
		if _, err = tx.ExecContext(ctx, `
UPDATE tunnels
SET state = ?, disconnected_at = ?
WHERE domain_id = ? AND state = ?`,
			domain.TunnelStateDisconnected, now, domainID, domain.TunnelStateConnected); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `
UPDATE domains
SET status = ?
WHERE id = ?`, domain.DomainStatusActive, domainID); err != nil {
			return err
		}

		tID2, err := newID("t")
		if err != nil {
			return err
		}
		t = domain.Tunnel{
			ID:          tID2,
			APIKeyID:    keyID,
			DomainID:    domainID,
			State:       domain.TunnelStateDisconnected,
			IsTemporary: domainType == domain.DomainTypeTemporarySubdomain,
			ClientMeta:  clientMeta,
		}
		if _, err = tx.ExecContext(ctx, `
INSERT INTO tunnels(id, api_key_id, domain_id, state, is_temporary, client_meta, access_user, access_mode, access_password_hash, connected_at, disconnected_at)
VALUES(?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL)`,
			t.ID, t.APIKeyID, t.DomainID, t.State, boolToInt(t.IsTemporary), nullableString(t.ClientMeta)); err != nil {
			return err
		}

		return tx.Commit()
	})
	if err != nil {
		return domain.Tunnel{}, err
	}
	return t, nil
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
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
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
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
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
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
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
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
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
