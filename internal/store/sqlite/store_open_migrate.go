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

	resolveAPIKeyIDStmt      *sql.Stmt
	activeTunnelCountStmt    *sql.Stmt
	getAPIKeyTunnelLimitStmt *sql.Stmt
	isHostnameActiveStmt     *sql.Stmt
	findRouteByHostStmt      *sql.Stmt

	writeRequests        chan storeWriteRequest
	touchRequests        chan storeTouchRequest
	writerStop           chan struct{}
	writerDone           chan struct{}
	touchMu              sync.Mutex
	lastDomainTouch      map[string]time.Time
	touchMinInterval     time.Duration
	touchCleanupInterval time.Duration
	nextTouchCleanupAt   time.Time
	touchFlushInterval   time.Duration
}

const defaultTouchMinInterval = 30 * time.Second
const defaultTouchCleanupInterval = 5 * time.Minute
const defaultConnectTokenPurgeLimit = 1000
const defaultWriteQueueSize = 4096
const defaultTouchQueueSize = 4096
const defaultTouchFlushInterval = 250 * time.Millisecond

const defaultMaxOpenConns = 10
const defaultMaxIdleConns = 10

const resolveAPIKeyIDQuery = `SELECT id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`
const activeTunnelCountByKeyQuery = `SELECT COUNT(1) FROM tunnels WHERE api_key_id = ? AND state = ?`
const isHostnameActiveQuery = `SELECT 1 FROM domains WHERE hostname = ? AND status = ? LIMIT 1`
const findRouteByHostQuery = `
SELECT
 d.id, d.api_key_id, d.type, d.hostname, d.status, d.created_at, d.last_seen_at,
 t.id, t.api_key_id, t.domain_id, t.state, t.is_temporary, t.client_meta, t.access_user, t.access_mode, t.access_password_hash, t.connected_at, t.disconnected_at
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
	dsn := path + sep + "_pragma=foreign_keys(1)&_pragma=synchronous(normal)&_pragma=busy_timeout(5000)"
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

	// journal_mode is database-wide; set it once here.
	// foreign_keys, synchronous, and busy_timeout are per-connection and are handled via DSN _pragma parameters.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
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
		touchFlushInterval:   defaultTouchFlushInterval,
		writeRequests:        make(chan storeWriteRequest, defaultWriteQueueSize),
		touchRequests:        make(chan storeTouchRequest, defaultTouchQueueSize),
		writerStop:           make(chan struct{}),
		writerDone:           make(chan struct{}),
	}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	go s.runWriterLoop()
	if err := s.prepareStatements(context.Background()); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	s.stopWriterLoop()
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
	if s.getAPIKeyTunnelLimitStmt, err = s.db.PrepareContext(ctx, getAPIKeyTunnelLimitQuery); err != nil {
		closeErr := s.closePreparedStatements()
		return errors.Join(fmt.Errorf("prepare api key tunnel limit query: %w", err), closeErr)
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
	err = errors.Join(err, closeStmt(&s.getAPIKeyTunnelLimitStmt))
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

type schemaMigration struct {
	version int
	name    string
	apply   func(context.Context, *sql.Tx) error
}

var schemaMigrations = []schemaMigration{
	{version: 1, name: "base_schema", apply: applyBaseSchemaMigration},
	{version: 2, name: "tunnels_access_password_hash", apply: func(ctx context.Context, tx *sql.Tx) error {
		return ensureColumn(ctx, tx, "tunnels", "access_password_hash", `ALTER TABLE tunnels ADD COLUMN access_password_hash TEXT NULL`)
	}},
	{version: 3, name: "tunnels_access_user", apply: func(ctx context.Context, tx *sql.Tx) error {
		return ensureColumn(ctx, tx, "tunnels", "access_user", `ALTER TABLE tunnels ADD COLUMN access_user TEXT NULL`)
	}},
	{version: 4, name: "tunnels_access_mode", apply: func(ctx context.Context, tx *sql.Tx) error {
		return ensureColumn(ctx, tx, "tunnels", "access_mode", `ALTER TABLE tunnels ADD COLUMN access_mode TEXT NULL`)
	}},
	{version: 5, name: "api_keys_tunnel_limit", apply: func(ctx context.Context, tx *sql.Tx) error {
		return ensureColumn(ctx, tx, "api_keys", "tunnel_limit", `ALTER TABLE api_keys ADD COLUMN tunnel_limit INTEGER NOT NULL DEFAULT -1`)
	}},
}

// Migrate creates all required tables and indexes if they do not already exist.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at DATETIME NOT NULL
)`); err != nil {
		return err
	}
	for _, migration := range schemaMigrations {
		if err := applySchemaMigration(ctx, s.db, migration); err != nil {
			return fmt.Errorf("schema migration %d (%s): %w", migration.version, migration.name, err)
		}
	}
	return nil
}

func applyBaseSchemaMigration(ctx context.Context, tx *sql.Tx) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS api_keys (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL UNIQUE,
	created_at DATETIME NOT NULL,
	revoked_at DATETIME NULL,
	tunnel_limit INTEGER NOT NULL DEFAULT -1
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
	access_mode TEXT NULL,
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
	_, err := tx.ExecContext(ctx, ddl)
	return err
}

func applySchemaMigration(ctx context.Context, db *sql.DB, migration schemaMigration) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	applied, err := schemaMigrationApplied(ctx, tx, migration.version)
	if err != nil {
		return err
	}
	if applied {
		return tx.Commit()
	}
	if err := migration.apply(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, name, applied_at) VALUES(?, ?, ?)`, migration.version, migration.name, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func schemaMigrationApplied(ctx context.Context, tx *sql.Tx, version int) (bool, error) {
	var applied int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations WHERE version = ?`, version).Scan(&applied)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

func ensureColumn(ctx context.Context, tx *sql.Tx, table, column, ddl string) error {
	hasColumn, err := tableHasColumn(ctx, tx, table, column)
	if err != nil {
		return err
	}
	if hasColumn {
		return nil
	}
	_, err = tx.ExecContext(ctx, ddl)
	return err
}

func tableHasColumn(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s)", quoteSQLiteIdent(table))
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			cid          int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(column)) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func quoteSQLiteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
