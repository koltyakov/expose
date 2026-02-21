package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
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
		return 0, err
	}

	res, err := tx.ExecContext(ctx, `
UPDATE tunnels
SET state = ?, disconnected_at = ?
WHERE state = ?`, domain.TunnelStateDisconnected, time.Now().UTC(), domain.TunnelStateConnected)
	if err != nil {
		return 0, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	if err = tx.Commit(); err != nil {
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	d, err := s.claimOrCreateDomainTx(ctx, tx, keyID, in, now)
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	t, err := insertAllocatedTunnelTx(ctx, tx, keyID, d.ID, in.isTemporary, in.clientMeta)
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}

	if err = tx.Commit(); err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	return d, t, nil
}

func (s *Store) SwapTunnelSession(ctx context.Context, domainID, keyID, clientMeta string) (domain.Tunnel, error) {
	clientMeta = strings.TrimSpace(clientMeta)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Tunnel{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var apiKeyID string
	var domainType string
	if err = tx.QueryRowContext(ctx, `
SELECT api_key_id, type
FROM domains
WHERE id = ?`, domainID).Scan(&apiKeyID, &domainType); err != nil {
		return domain.Tunnel{}, err
	}
	if apiKeyID != keyID {
		return domain.Tunnel{}, ErrHostnameInUse
	}

	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `
UPDATE tunnels
SET state = ?, disconnected_at = ?
WHERE domain_id = ? AND state = ?`,
		domain.TunnelStateDisconnected, now, domainID, domain.TunnelStateConnected); err != nil {
		return domain.Tunnel{}, err
	}
	if _, err = tx.ExecContext(ctx, `
UPDATE domains
SET status = ?
WHERE id = ?`, domain.DomainStatusActive, domainID); err != nil {
		return domain.Tunnel{}, err
	}

	tID2, err := newID("t")
	if err != nil {
		return domain.Tunnel{}, err
	}
	t := domain.Tunnel{
		ID:          tID2,
		APIKeyID:    keyID,
		DomainID:    domainID,
		State:       domain.TunnelStateDisconnected,
		IsTemporary: domainType == domain.DomainTypeTemporarySubdomain,
		ClientMeta:  clientMeta,
	}
	if _, err = tx.ExecContext(ctx, `
INSERT INTO tunnels(id, api_key_id, domain_id, state, is_temporary, client_meta, access_user, access_password_hash, connected_at, disconnected_at)
VALUES(?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)`,
		t.ID, t.APIKeyID, t.DomainID, t.State, boolToInt(t.IsTemporary), nullableString(t.ClientMeta)); err != nil {
		return domain.Tunnel{}, err
	}

	if err = tx.Commit(); err != nil {
		return domain.Tunnel{}, err
	}
	return t, nil
}

func (s *Store) SetTunnelConnected(ctx context.Context, tunnelID string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE tunnels
SET state = ?, connected_at = ?, disconnected_at = NULL
WHERE id = ?`,
		domain.TunnelStateConnected, time.Now().UTC(), tunnelID)
	return err
}

func (s *Store) SetTunnelAccessCredentials(ctx context.Context, tunnelID, user, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE tunnels SET access_user = ?, access_password_hash = ? WHERE id = ?`, nullableString(user), nullableString(hash), tunnelID)
	return err
}

func (s *Store) SetTunnelAccessPasswordHash(ctx context.Context, tunnelID, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE tunnels SET access_user = ?, access_password_hash = ? WHERE id = ?`, "admin", nullableString(hash), tunnelID)
	return err
}

func (s *Store) SetTunnelDisconnected(ctx context.Context, tunnelID string) error {
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
		if err = tx.Commit(); err != nil {
			return err
		}
		return nil
	}

	if _, err = tx.ExecContext(ctx, `UPDATE tunnels SET state = ?, disconnected_at = ? WHERE id = ?`, domain.TunnelStateDisconnected, time.Now().UTC(), tunnelID); err != nil {
		return err
	}

	if isTemp {
		if _, err = tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusInactive, domainID); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *Store) CloseTemporaryTunnel(ctx context.Context, tunnelID string) (string, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback() }()

	var state string
	var isTemp bool
	var domainID string
	var domainType string
	var hostname string
	if err = tx.QueryRowContext(ctx, `
SELECT t.state, t.is_temporary, t.domain_id, d.type, d.hostname
FROM tunnels t
JOIN domains d ON d.id = t.domain_id
WHERE t.id = ?`, tunnelID).Scan(&state, &isTemp, &domainID, &domainType, &hostname); err != nil {
		return "", false, err
	}

	if !isTemp || domainType != domain.DomainTypeTemporarySubdomain {
		if err = tx.Commit(); err != nil {
			return "", false, err
		}
		return "", false, nil
	}
	if state == domain.TunnelStateClosed {
		if err = tx.Commit(); err != nil {
			return "", false, err
		}
		return hostname, false, nil
	}

	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE tunnels SET state = ?, disconnected_at = ? WHERE id = ?`, domain.TunnelStateClosed, now, tunnelID); err != nil {
		return "", false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusInactive, domainID); err != nil {
		return "", false, err
	}

	if err = tx.Commit(); err != nil {
		return "", false, err
	}
	return hostname, true, nil
}
