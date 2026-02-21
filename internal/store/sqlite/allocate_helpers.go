package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

type allocationInput struct {
	isTemporary bool
	domainType  string
	hostname    string
	clientMeta  string
}

func (s *Store) buildAllocationInput(ctx context.Context, mode, subdomain, baseDomain, clientMeta string) (allocationInput, error) {
	baseDomain = strings.ToLower(strings.TrimSpace(baseDomain))
	subdomain = normalizeHostLabel(subdomain)
	clientMeta = strings.TrimSpace(clientMeta)

	isTemporary := mode == "temporary"
	domainType := domain.DomainTypePermanentSubdomain
	if isTemporary {
		domainType = domain.DomainTypeTemporarySubdomain
		if subdomain == "" {
			gen, err := s.generateSubdomain(ctx, baseDomain)
			if err != nil {
				return allocationInput{}, err
			}
			subdomain = gen
		}
	} else if subdomain == "" {
		return allocationInput{}, errors.New("permanent mode requires subdomain")
	}

	return allocationInput{
		isTemporary: isTemporary,
		domainType:  domainType,
		hostname:    fmt.Sprintf("%s.%s", subdomain, baseDomain),
		clientMeta:  clientMeta,
	}, nil
}

func (s *Store) claimOrCreateDomainTx(
	ctx context.Context,
	tx *sql.Tx,
	keyID string,
	in allocationInput,
	now time.Time,
) (domain.Domain, error) {
	dID, err := newID("d")
	if err != nil {
		return domain.Domain{}, err
	}

	d := domain.Domain{
		ID:        dID,
		APIKeyID:  keyID,
		Type:      in.domainType,
		Hostname:  in.hostname,
		Status:    domain.DomainStatusActive,
		CreatedAt: now,
	}

	if in.isTemporary {
		return s.claimOrCreateTemporaryDomainTx(ctx, tx, d, keyID)
	}
	return s.claimOrCreatePermanentDomainTx(ctx, tx, d, keyID)
}

func (s *Store) claimOrCreatePermanentDomainTx(
	ctx context.Context,
	tx *sql.Tx,
	d domain.Domain,
	keyID string,
) (domain.Domain, error) {
	var existingID string
	err := tx.QueryRowContext(ctx, `
SELECT id FROM domains
WHERE hostname = ? AND api_key_id = ? AND type = ?`,
		d.Hostname, keyID, domain.DomainTypePermanentSubdomain).Scan(&existingID)
	if err == nil {
		if connected, err := domainHasConnectedTunnelTx(ctx, tx, existingID); err != nil {
			return domain.Domain{}, err
		} else if connected {
			return domain.Domain{}, ErrHostnameInUse
		}
		d.ID = existingID
		if _, err := tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusActive, existingID); err != nil {
			return domain.Domain{}, err
		}
		return d, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Domain{}, err
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO domains(id, api_key_id, type, hostname, status, created_at, last_seen_at)
VALUES(?, ?, ?, ?, ?, ?, NULL)`, d.ID, d.APIKeyID, d.Type, d.Hostname, d.Status, d.CreatedAt); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return domain.Domain{}, ErrHostnameInUse
		}
		return domain.Domain{}, err
	}
	return d, nil
}

func (s *Store) claimOrCreateTemporaryDomainTx(
	ctx context.Context,
	tx *sql.Tx,
	d domain.Domain,
	keyID string,
) (domain.Domain, error) {
	var existingID, existingAPIKeyID, existingType string
	err := tx.QueryRowContext(ctx, `
SELECT id, api_key_id, type
FROM domains
WHERE hostname = ?`, d.Hostname).Scan(&existingID, &existingAPIKeyID, &existingType)
	if err == nil {
		if existingAPIKeyID != keyID || existingType != domain.DomainTypeTemporarySubdomain {
			return domain.Domain{}, ErrHostnameInUse
		}
		if connected, err := domainHasConnectedTunnelTx(ctx, tx, existingID); err != nil {
			return domain.Domain{}, err
		} else if connected {
			return domain.Domain{}, ErrHostnameInUse
		}
		d.ID = existingID
		if _, err := tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusActive, existingID); err != nil {
			return domain.Domain{}, err
		}
		return d, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Domain{}, err
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO domains(id, api_key_id, type, hostname, status, created_at, last_seen_at)
VALUES(?, ?, ?, ?, ?, ?, NULL)`, d.ID, d.APIKeyID, d.Type, d.Hostname, d.Status, d.CreatedAt); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return domain.Domain{}, ErrHostnameInUse
		}
		return domain.Domain{}, err
	}
	return d, nil
}

func domainHasConnectedTunnelTx(ctx context.Context, tx *sql.Tx, domainID string) (bool, error) {
	var connectedCount int
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM tunnels
WHERE domain_id = ? AND state = ?`, domainID, domain.TunnelStateConnected).Scan(&connectedCount); err != nil {
		return false, err
	}
	return connectedCount > 0, nil
}

func insertAllocatedTunnelTx(
	ctx context.Context,
	tx *sql.Tx,
	keyID string,
	domainID string,
	isTemporary bool,
	clientMeta string,
) (domain.Tunnel, error) {
	tID, err := newID("t")
	if err != nil {
		return domain.Tunnel{}, err
	}
	t := domain.Tunnel{
		ID:          tID,
		APIKeyID:    keyID,
		DomainID:    domainID,
		State:       domain.TunnelStateDisconnected,
		IsTemporary: isTemporary,
		ClientMeta:  clientMeta,
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO tunnels(id, api_key_id, domain_id, state, is_temporary, client_meta, access_user, access_password_hash, connected_at, disconnected_at)
VALUES(?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)`,
		t.ID, t.APIKeyID, t.DomainID, t.State, boolToInt(t.IsTemporary), nullableString(t.ClientMeta)); err != nil {
		return domain.Tunnel{}, err
	}
	return t, nil
}
