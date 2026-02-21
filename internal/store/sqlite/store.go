// Package sqlite implements the expose data store backed by a SQLite database.
// It manages API keys, domains, tunnels, connect tokens, and server settings.
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
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
)

// ErrHostnameInUse is returned when the requested hostname is already allocated
// by another key or tunnel type and cannot be claimed by the caller.
var ErrHostnameInUse = errors.New("hostname already in use")

// Store wraps a SQLite database connection for all expose persistence operations.
type Store struct {
	db *sql.DB

	touchMu              sync.Mutex
	lastDomainTouch      map[string]time.Time
	touchMinInterval     time.Duration
	touchCleanupInterval time.Duration
	nextTouchCleanupAt   time.Time
}

const defaultTouchMinInterval = 30 * time.Second
const defaultTouchCleanupInterval = 5 * time.Minute
const defaultConnectTokenPurgeLimit = 1000

const defaultMaxOpenConns = 10
const defaultMaxIdleConns = 10

// OpenOptions controls SQLite connection pool sizing.
type OpenOptions struct {
	MaxOpenConns int
	MaxIdleConns int
}

// Open creates or opens the SQLite database at path, runs migrations, and
// enables WAL mode for improved concurrent read performance.
func Open(path string) (*Store, error) {
	return OpenWithOptions(path, OpenOptions{})
}

// OpenWithOptions creates or opens the SQLite database at path with tunable
// connection pool settings, runs migrations, and enables WAL mode.
func OpenWithOptions(path string, opts OpenOptions) (*Store, error) {
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}
	// Append per-connection PRAGMAs to the DSN so every pooled connection gets them.
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	dsn := path + sep + "_pragma=foreign_keys(1)&_pragma=synchronous(normal)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Default is conservative (1/1), but can be raised for read-heavy workloads.
	maxOpenConns := opts.MaxOpenConns
	if maxOpenConns <= 0 {
		maxOpenConns = defaultMaxOpenConns
	}
	maxIdleConns := opts.MaxIdleConns
	if maxIdleConns <= 0 {
		maxIdleConns = defaultMaxIdleConns
	}
	if maxIdleConns > maxOpenConns {
		maxIdleConns = maxOpenConns
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	// journal_mode and busy_timeout are database-wide; set them once here.
	// foreign_keys and synchronous are per-connection and are handled via DSN _pragma parameters.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite setup (%s): %w", pragma, err)
		}
	}
	now := time.Now().UTC()
	s := &Store{
		db:                   db,
		lastDomainTouch:      make(map[string]time.Time),
		touchMinInterval:     defaultTouchMinInterval,
		touchCleanupInterval: defaultTouchCleanupInterval,
		nextTouchCleanupAt:   now.Add(defaultTouchCleanupInterval),
	}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Migrate creates all required tables and indexes if they do not already exist.
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
	access_user TEXT NULL,
	access_password_hash TEXT NULL,
	connected_at DATETIME NULL,
	disconnected_at DATETIME NULL
);
CREATE TABLE IF NOT EXISTS connect_tokens (
	token TEXT PRIMARY KEY,
	tunnel_id TEXT NOT NULL,
	expires_at DATETIME NOT NULL,
	used_at DATETIME NULL
);
CREATE TABLE IF NOT EXISTS server_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_hostname ON domains(hostname);
CREATE INDEX IF NOT EXISTS idx_tunnels_state ON tunnels(state);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_domains_type_status ON domains(type, status);
CREATE INDEX IF NOT EXISTS idx_tunnels_domain_id ON tunnels(domain_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_domain_state ON tunnels(domain_id, state);
CREATE INDEX IF NOT EXISTS idx_tunnels_api_key_state ON tunnels(api_key_id, state);
CREATE INDEX IF NOT EXISTS idx_tunnels_domain_connected_at ON tunnels(domain_id, connected_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_connect_tokens_tunnel_id ON connect_tokens(tunnel_id);
CREATE INDEX IF NOT EXISTS idx_connect_tokens_expires_at ON connect_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_connect_tokens_used_at ON connect_tokens(used_at);
`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE tunnels ADD COLUMN access_password_hash TEXT NULL`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE tunnels ADD COLUMN access_user TEXT NULL`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}

func (s *Store) CreateAPIKey(ctx context.Context, name, keyHash string) (domain.APIKey, error) {
	now := time.Now().UTC()
	id, err := newID("k")
	if err != nil {
		return domain.APIKey{}, err
	}
	k := domain.APIKey{
		ID:        id,
		Name:      name,
		KeyHash:   keyHash,
		CreatedAt: now,
	}
	_, err = s.db.ExecContext(ctx, `
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
	defer func() { _ = rows.Close() }()

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

func (s *Store) ActiveTunnelCountByKey(ctx context.Context, keyID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM tunnels WHERE api_key_id = ? AND state = ?`, keyID, domain.TunnelStateConnected).Scan(&count)
	return count, err
}

func (s *Store) IsHostnameActive(ctx context.Context, host string) (bool, error) {
	host = normalizeHostname(host)
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE hostname = ? AND status = ? LIMIT 1`, host, domain.DomainStatusActive).Scan(&one)
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
	baseDomain = strings.ToLower(strings.TrimSpace(baseDomain))
	subdomain = normalizeHostLabel(subdomain)
	clientMeta = strings.TrimSpace(clientMeta)

	isTemporary := mode == "temporary"
	var dType string
	var hostname string
	if isTemporary {
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
			return domain.Domain{}, domain.Tunnel{}, errors.New("permanent mode requires subdomain")
		}
		hostname = fmt.Sprintf("%s.%s", subdomain, baseDomain)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	dID, err := newID("d")
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	d := domain.Domain{
		ID:        dID,
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
WHERE hostname = ? AND api_key_id = ? AND type = ?`,
			hostname, keyID, domain.DomainTypePermanentSubdomain).Scan(&existingID)
		if err == nil {
			// Reject if there is already a connected tunnel for this domain.
			var connectedCount int
			if err = tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM tunnels
WHERE domain_id = ? AND state = ?`, existingID, domain.TunnelStateConnected).Scan(&connectedCount); err != nil {
				return domain.Domain{}, domain.Tunnel{}, err
			}
			if connectedCount > 0 {
				return domain.Domain{}, domain.Tunnel{}, ErrHostnameInUse
			}
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
					return domain.Domain{}, domain.Tunnel{}, ErrHostnameInUse
				}
				return domain.Domain{}, domain.Tunnel{}, err
			}
		}
	} else {
		var existingID, existingAPIKeyID, existingType string
		err = tx.QueryRowContext(ctx, `
SELECT id, api_key_id, type
FROM domains
WHERE hostname = ?`, d.Hostname).Scan(&existingID, &existingAPIKeyID, &existingType)
		if err == nil {
			if existingAPIKeyID != keyID || existingType != domain.DomainTypeTemporarySubdomain {
				return domain.Domain{}, domain.Tunnel{}, ErrHostnameInUse
			}
			// Reject if there is already a connected tunnel for this domain.
			var connectedCount int
			if err = tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM tunnels
WHERE domain_id = ? AND state = ?`, existingID, domain.TunnelStateConnected).Scan(&connectedCount); err != nil {
				return domain.Domain{}, domain.Tunnel{}, err
			}
			if connectedCount > 0 {
				return domain.Domain{}, domain.Tunnel{}, ErrHostnameInUse
			}
			d.ID = existingID
			if _, err = tx.ExecContext(ctx, `UPDATE domains SET status = ? WHERE id = ?`, domain.DomainStatusActive, existingID); err != nil {
				return domain.Domain{}, domain.Tunnel{}, err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return domain.Domain{}, domain.Tunnel{}, err
		} else {
			if _, err = tx.ExecContext(ctx, `
INSERT INTO domains(id, api_key_id, type, hostname, status, created_at, last_seen_at)
VALUES(?, ?, ?, ?, ?, ?, NULL)`, d.ID, d.APIKeyID, d.Type, d.Hostname, d.Status, d.CreatedAt); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") {
					return domain.Domain{}, domain.Tunnel{}, ErrHostnameInUse
				}
				return domain.Domain{}, domain.Tunnel{}, err
			}
		}
	}

	tID, err := newID("t")
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, err
	}
	t := domain.Tunnel{
		ID:          tID,
		APIKeyID:    keyID,
		DomainID:    d.ID,
		State:       domain.TunnelStateDisconnected,
		IsTemporary: isTemporary,
		ClientMeta:  clientMeta,
	}

	if _, err = tx.ExecContext(ctx, `
INSERT INTO tunnels(id, api_key_id, domain_id, state, is_temporary, client_meta, access_user, access_password_hash, connected_at, disconnected_at)
VALUES(?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)`,
		t.ID, t.APIKeyID, t.DomainID, t.State, boolToInt(t.IsTemporary), nullableString(t.ClientMeta)); err != nil {
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

func (s *Store) FindRouteByHost(ctx context.Context, host string) (domain.TunnelRoute, error) {
	host = normalizeHostname(host)
	var r domain.TunnelRoute
	var lastSeen sql.NullTime
	var connectedAt sql.NullTime
	var disconnectedAt sql.NullTime
	var clientMeta sql.NullString
	var accessUser sql.NullString
	var accessPasswordHash sql.NullString

	err := s.db.QueryRowContext(ctx, `
SELECT
 d.id, d.api_key_id, d.type, d.hostname, d.status, d.created_at, d.last_seen_at,
 t.id, t.api_key_id, t.domain_id, t.state, t.is_temporary, t.client_meta, t.access_user, t.access_password_hash, t.connected_at, t.disconnected_at
FROM domains d
JOIN tunnels t ON t.id = (
	SELECT id
	FROM tunnels
	WHERE domain_id = d.id
	ORDER BY connected_at DESC, id DESC
	LIMIT 1
)
WHERE d.hostname = ?
LIMIT 1`, host).Scan(
		&r.Domain.ID, &r.Domain.APIKeyID, &r.Domain.Type, &r.Domain.Hostname, &r.Domain.Status, &r.Domain.CreatedAt, &lastSeen,
		&r.Tunnel.ID, &r.Tunnel.APIKeyID, &r.Tunnel.DomainID, &r.Tunnel.State, &r.Tunnel.IsTemporary, &clientMeta, &accessUser, &accessPasswordHash, &connectedAt, &disconnectedAt,
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
	if accessUser.Valid {
		r.Tunnel.AccessUser = accessUser.String
	}
	if accessPasswordHash.Valid {
		r.Tunnel.AccessPasswordHash = accessPasswordHash.String
	}
	if disconnectedAt.Valid {
		t := disconnectedAt.Time
		r.Tunnel.DisconnectedAt = &t
	}
	return r, nil
}

func (s *Store) TouchDomain(ctx context.Context, domainID string) error {
	now := time.Now().UTC()
	if !s.reserveDomainTouch(domainID, now) {
		return nil
	}

	_, err := s.db.ExecContext(ctx, `UPDATE domains SET last_seen_at = ? WHERE id = ?`, now, domainID)
	if err != nil {
		s.rollbackDomainTouch(domainID, now)
	}
	return err
}

func (s *Store) reserveDomainTouch(domainID string, now time.Time) bool {
	domainID = strings.TrimSpace(domainID)
	if domainID == "" {
		return false
	}

	s.touchMu.Lock()
	defer s.touchMu.Unlock()

	if now.After(s.nextTouchCleanupAt) {
		s.cleanupStaleTouchEntriesLocked(now)
		s.nextTouchCleanupAt = now.Add(s.touchCleanupInterval)
	}
	if last, ok := s.lastDomainTouch[domainID]; ok && now.Sub(last) < s.touchMinInterval {
		return false
	}
	s.lastDomainTouch[domainID] = now
	return true
}

func (s *Store) rollbackDomainTouch(domainID string, reservedAt time.Time) {
	s.touchMu.Lock()
	defer s.touchMu.Unlock()

	if last, ok := s.lastDomainTouch[domainID]; ok && last.Equal(reservedAt) {
		delete(s.lastDomainTouch, domainID)
	}
}

func (s *Store) cleanupStaleTouchEntriesLocked(now time.Time) {
	cutoff := now.Add(-(s.touchMinInterval * 4))
	for domainID, last := range s.lastDomainTouch {
		if last.Before(cutoff) {
			delete(s.lastDomainTouch, domainID)
		}
	}
}

func (s *Store) generateSubdomain(ctx context.Context, baseDomain string) (string, error) {
	const attempts = 16
	slugs := make([]string, 0, attempts)
	hostnames := make([]any, 0, attempts)
	slugByHostname := make(map[string]struct{}, attempts)
	for i := 0; i < attempts; i++ {
		slug, err := randomSlug(6)
		if err != nil {
			return "", err
		}
		hostname := fmt.Sprintf("%s.%s", slug, baseDomain)
		if _, dup := slugByHostname[hostname]; dup {
			continue
		}
		slugs = append(slugs, slug)
		hostnames = append(hostnames, hostname)
		slugByHostname[hostname] = struct{}{}
	}
	if len(hostnames) == 0 {
		return "", errors.New("failed to generate subdomain candidates")
	}

	placeholders := strings.Repeat("?,", len(hostnames))
	placeholders = placeholders[:len(placeholders)-1]
	rows, err := s.db.QueryContext(ctx, `SELECT hostname FROM domains WHERE hostname IN (`+placeholders+`)`, hostnames...)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	taken := make(map[string]struct{}, len(hostnames))
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return "", err
		}
		taken[h] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	for _, slug := range slugs {
		hostname := fmt.Sprintf("%s.%s", slug, baseDomain)
		if _, conflict := taken[hostname]; !conflict {
			return slug, nil
		}
	}
	return "", errors.New("failed to generate unique subdomain")
}

func normalizeHostname(host string) string {
	return netutil.NormalizeHost(host)
}

func normalizeHostLabel(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func randomSlug(length int) (string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	const n = byte(len(alphabet))
	// Rejection threshold avoids modulo bias: largest multiple of n <= 256.
	const maxFair = 256 - (256 % int(n))
	slug := make([]byte, length)
	buf := make([]byte, length+16) // over-read to reduce rand calls
	filled := 0
	for filled < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("crypto/rand: %w", err)
		}
		for _, b := range buf {
			if int(b) >= maxFair {
				continue
			}
			slug[filled] = alphabet[b%n]
			filled++
			if filled == length {
				break
			}
		}
	}
	return string(slug), nil
}

func newID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func nullableString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
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
