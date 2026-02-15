package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/koltyakov/expose/internal/domain"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS api_keys (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL UNIQUE,
	created_at DATETIME NOT NULL,
	revoked_at DATETIME NULL
);
CREATE TABLE IF NOT EXISTS domains (
	id TEXT PRIMARY KEY,
	api_key_id TEXT NOT NULL,
	type TEXT NOT NULL,
	hostname TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	last_seen_at DATETIME NULL
);
CREATE TABLE IF NOT EXISTS tunnels (
	id TEXT PRIMARY KEY,
	api_key_id TEXT NOT NULL,
	domain_id TEXT NOT NULL,
	state TEXT NOT NULL,
	is_temporary INTEGER NOT NULL,
	client_meta TEXT NULL,
	connected_at DATETIME NULL,
	disconnected_at DATETIME NULL
);
CREATE TABLE IF NOT EXISTS connect_tokens (
	token TEXT PRIMARY KEY,
	tunnel_id TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	used_at DATETIME NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_hostname ON domains(hostname);
CREATE INDEX IF NOT EXISTS idx_tunnels_state ON tunnels(state);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
`
	_, err := s.db.ExecContext(ctx, ddl)
	return err
}

func (s *Store) CreateAPIKey(ctx context.Context, name, keyHash string) (domain.APIKey, error) {
	now := time.Now().UTC()
	k := domain.APIKey{
		ID:        newID("k"),
		Name:      name,
		KeyHash:   keyHash,
		CreatedAt: now,
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO api_keys(id, name, key_hash, created_at, revoked_at)
VALUES(?, ?, ?, ?, NULL)`, k.ID, k.Name, k.KeyHash, k.CreatedAt)
	return k, err
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, key_hash, created_at, revoked_at
FROM api_keys
ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.APIKey
	for rows.Next() {
		var k domain.APIKey
		var revoked sql.NullTime
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyHash, &k.CreatedAt, &revoked); err != nil {
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
	err := s.db.QueryRowContext(ctx, `SELECT id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`, keyHash).Scan(&id)
	return id, err
}

func (s *Store) ActiveTunnelCountByKey(ctx context.Context, keyID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM tunnels WHERE api_key_id = ? AND state = ?`, keyID, domain.TunnelStateConnected).Scan(&count)
	return count, err
}

func (s *Store) AllocateDomainAndTunnel(ctx context.Context, keyID, mode, subdomain, customDomain, baseDomain string) (domain.Domain, domain.Tunnel, error) {
	baseDomain = strings.ToLower(strings.TrimSpace(baseDomain))
	subdomain = normalizeHostLabel(subdomain)
	customDomain = normalizeHostname(customDomain)

	isTemporary := mode == "temporary"
	var dType string
	var hostname string
	if customDomain != "" {
		dType = domain.DomainTypeCustom
		hostname = customDomain
	} else if isTemporary {
		dType = domain.DomainTypeTemporarySubdomain
		if subdomain == "" {
			gen, err := s.generateSubdomain(ctx, baseDomain)
			if err != nil {
				return domain.Domain{}, domain.Tunnel{}, err
			}
			subdomain = gen
		}
		hostname = fmt.Sprintf("%s.%s", subdomain, baseDomain)
	} else {
		dType = domain.DomainTypePermanentSubdomain
		if subdomain == "" {
			return domain.Domain{}, domain.Tunnel{}, errors.New("permanent mode requires subdomain or custom domain")
		}
		hostname = fmt.Sprintf("%s.%s", subdomain, baseDomain)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	now := time.Now().UTC()
	d := domain.Domain{
		ID:        newID("d"),
		APIKeyID:  keyID,
		Type:      dType,
		Hostname:  hostname,
		Status:    domain.DomainStatusActive,
		CreatedAt: now,
	}

	if !isTemporary {
		var existingID string
		err = tx.QueryRowContext(ctx, `
SELECT id FROM domains
WHERE hostname = ? AND api_key_id = ? AND type IN (?, ?)`,
			hostname, keyID, domain.DomainTypePermanentSubdomain, domain.DomainTypeCustom).Scan(&existingID)
		if err == nil {
			d.ID = existingID
			_, err = tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusActive, existingID)
			if err != nil {
				return domain.Domain{}, domain.Tunnel{}, err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return domain.Domain{}, domain.Tunnel{}, err
		} else {
			if _, err = tx.ExecContext(ctx, `
INSERT INTO domains(id, api_key_id, type, hostname, status, created_at, last_seen_at)
VALUES(?, ?, ?, ?, ?, ?, NULL)`, d.ID, d.APIKeyID, d.Type, d.Hostname, d.Status, d.CreatedAt); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") {
					return domain.Domain{}, domain.Tunnel{}, errors.New("hostname already in use")
				}
				return domain.Domain{}, domain.Tunnel{}, err
			}
		}
	} else {
		if _, err = tx.ExecContext(ctx, `
INSERT INTO domains(id, api_key_id, type, hostname, status, created_at, last_seen_at)
VALUES(?, ?, ?, ?, ?, ?, NULL)`, d.ID, d.APIKeyID, d.Type, d.Hostname, d.Status, d.CreatedAt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				return domain.Domain{}, domain.Tunnel{}, errors.New("hostname already in use")
			}
			return domain.Domain{}, domain.Tunnel{}, err
		}
	}

	t := domain.Tunnel{
		ID:          newID("t"),
		APIKeyID:    keyID,
		DomainID:    d.ID,
		State:       domain.TunnelStateDisconnected,
		IsTemporary: isTemporary,
	}

	if _, err = tx.ExecContext(ctx, `
INSERT INTO tunnels(id, api_key_id, domain_id, state, is_temporary, client_meta, connected_at, disconnected_at)
VALUES(?, ?, ?, ?, ?, NULL, NULL, NULL)`,
		t.ID, t.APIKeyID, t.DomainID, t.State, boolToInt(t.IsTemporary)); err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}

	if err = tx.Commit(); err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	return d, t, nil
}

func (s *Store) CreateConnectToken(ctx context.Context, tunnelID string, ttl time.Duration) (string, error) {
	token := newID("ct")
	_, err := s.db.ExecContext(ctx, `
INSERT INTO connect_tokens(token, tunnel_id, expires_at, used_at)
VALUES(?, ?, ?, NULL)`, token, tunnelID, time.Now().UTC().Add(ttl))
	return token, err
}

func (s *Store) ConsumeConnectToken(ctx context.Context, token string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var tunnelID string
	var expires time.Time
	var used sql.NullTime
	if err = tx.QueryRowContext(ctx, `
SELECT tunnel_id, expires_at, used_at
FROM connect_tokens
WHERE token = ?`, token).Scan(&tunnelID, &expires, &used); err != nil {
		return "", err
	}
	if used.Valid {
		return "", errors.New("token already used")
	}
	if time.Now().UTC().After(expires) {
		return "", errors.New("token expired")
	}

	if _, err = tx.ExecContext(ctx, `UPDATE connect_tokens SET used_at = ? WHERE token = ?`, time.Now().UTC(), token); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return tunnelID, nil
}

func (s *Store) SetTunnelConnected(ctx context.Context, tunnelID string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE tunnels
SET state = ?, connected_at = ?, disconnected_at = NULL
WHERE id = ?`,
		domain.TunnelStateConnected, time.Now().UTC(), tunnelID)
	return err
}

func (s *Store) SetTunnelDisconnected(ctx context.Context, tunnelID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var isTemp bool
	var domainID string
	if err = tx.QueryRowContext(ctx, `SELECT is_temporary, domain_id FROM tunnels WHERE id = ?`, tunnelID).Scan(&isTemp, &domainID); err != nil {
		return err
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

func (s *Store) FindRouteByHost(ctx context.Context, host string) (domain.TunnelRoute, error) {
	host = normalizeHostname(host)
	var r domain.TunnelRoute
	var lastSeen sql.NullTime
	var connectedAt sql.NullTime
	var disconnectedAt sql.NullTime
	var clientMeta sql.NullString

	err := s.db.QueryRowContext(ctx, `
SELECT
 d.id, d.api_key_id, d.type, d.hostname, d.status, d.created_at, d.last_seen_at,
 t.id, t.api_key_id, t.domain_id, t.state, t.is_temporary, t.client_meta, t.connected_at, t.disconnected_at
FROM domains d
JOIN tunnels t ON t.domain_id = d.id
WHERE d.hostname = ?
ORDER BY t.connected_at DESC
LIMIT 1`, host).Scan(
		&r.Domain.ID, &r.Domain.APIKeyID, &r.Domain.Type, &r.Domain.Hostname, &r.Domain.Status, &r.Domain.CreatedAt, &lastSeen,
		&r.Tunnel.ID, &r.Tunnel.APIKeyID, &r.Tunnel.DomainID, &r.Tunnel.State, &r.Tunnel.IsTemporary, &clientMeta, &connectedAt, &disconnectedAt,
	)
	if err != nil {
		return domain.TunnelRoute{}, err
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		r.Domain.LastSeenAt = &t
	}
	if connectedAt.Valid {
		t := connectedAt.Time
		r.Tunnel.ConnectedAt = &t
	}
	if clientMeta.Valid {
		r.Tunnel.ClientMeta = clientMeta.String
	}
	if disconnectedAt.Valid {
		t := disconnectedAt.Time
		r.Tunnel.DisconnectedAt = &t
	}
	return r, nil
}

func (s *Store) TouchDomain(ctx context.Context, domainID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE domains SET last_seen_at = ? WHERE id = ?`, time.Now().UTC(), domainID)
	return err
}

func (s *Store) generateSubdomain(ctx context.Context, baseDomain string) (string, error) {
	for i := 0; i < 16; i++ {
		candidate := randomSlug(6)
		hostname := fmt.Sprintf("%s.%s", candidate, baseDomain)
		var one int
		err := s.db.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE hostname = ?`, hostname).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("failed to generate unique subdomain")
}

func normalizeHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		return parts[0]
	}
	return host
}

func normalizeHostLabel(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func randomSlug(length int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, length)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ensureParentDir(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
