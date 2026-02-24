// Package sqlite implements the expose data store backed by a SQLite database.
// It manages API keys, domains, tunnels, connect tokens, and server settings.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ErrHostnameInUse is returned when the requested hostname is already allocated
// by another key or tunnel type and cannot be claimed by the caller.
var ErrHostnameInUse = errors.New("hostname already in use")

// Store wraps a SQLite database connection for all expose persistence operations.
type Store struct {
	db *sql.DB

	resolveAPIKeyIDStmt   *sql.Stmt
	activeTunnelCountStmt *sql.Stmt
	isHostnameActiveStmt  *sql.Stmt
	findRouteByHostStmt   *sql.Stmt

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

const resolveAPIKeyIDQuery = `SELECT id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`
const activeTunnelCountByKeyQuery = `SELECT COUNT(1) FROM tunnels WHERE api_key_id = ? AND state = ?`
const isHostnameActiveQuery = `SELECT 1 FROM domains WHERE hostname = ? AND status = ? LIMIT 1`
const findRouteByHostQuery = `
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
LIMIT 1`

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
	if err := s.prepareStatements(context.Background()); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	stmtErr := s.closePreparedStatements()
	return errors.Join(stmtErr, s.db.Close())
}

func (s *Store) prepareStatements(ctx context.Context) error {
	var err error
	if s.resolveAPIKeyIDStmt, err = s.db.PrepareContext(ctx, resolveAPIKeyIDQuery); err != nil {
		return fmt.Errorf("prepare resolve api key query: %w", err)
	}
	if s.activeTunnelCountStmt, err = s.db.PrepareContext(ctx, activeTunnelCountByKeyQuery); err != nil {
		closeErr := s.closePreparedStatements()
		return errors.Join(fmt.Errorf("prepare active tunnel count query: %w", err), closeErr)
	}
	if s.isHostnameActiveStmt, err = s.db.PrepareContext(ctx, isHostnameActiveQuery); err != nil {
		closeErr := s.closePreparedStatements()
		return errors.Join(fmt.Errorf("prepare hostname active query: %w", err), closeErr)
	}
	if s.findRouteByHostStmt, err = s.db.PrepareContext(ctx, findRouteByHostQuery); err != nil {
		closeErr := s.closePreparedStatements()
		return errors.Join(fmt.Errorf("prepare find route query: %w", err), closeErr)
	}
	return nil
}

func (s *Store) closePreparedStatements() error {
	var err error
	err = errors.Join(err, closeStmt(&s.resolveAPIKeyIDStmt))
	err = errors.Join(err, closeStmt(&s.activeTunnelCountStmt))
	err = errors.Join(err, closeStmt(&s.isHostnameActiveStmt))
	err = errors.Join(err, closeStmt(&s.findRouteByHostStmt))
	return err
}

func closeStmt(stmt **sql.Stmt) error {
	if stmt == nil || *stmt == nil {
		return nil
	}
	err := (*stmt).Close()
	*stmt = nil
	return err
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
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE api_keys ADD COLUMN tunnel_limit INTEGER NOT NULL DEFAULT -1`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}
