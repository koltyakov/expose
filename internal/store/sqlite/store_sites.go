package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func (s *Store) CreatePublishedSite(ctx context.Context, site domain.PublishedSite) error {
	return s.withSerializedWrite(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		_, err = tx.ExecContext(ctx, `INSERT INTO domains(id, api_key_id, type, hostname, status, created_at) VALUES(?, ?, 'published_site', ?, 'active', ?)`, site.ID, site.APIKeyID, site.Hostname, site.CreatedAt)
		if err != nil {
			return siteConflictError(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO published_sites(id, api_key_id, hostname, created_at, expires_at, source_id, content_id) VALUES(?, ?, ?, ?, ?, ?, ?)`, site.ID, site.APIKeyID, site.Hostname, site.CreatedAt, site.ExpiresAt, site.SourceID, site.ContentID)
		if err != nil {
			return err
		}
		return tx.Commit()
	})
}

func siteConflictError(err error) error {
	if strings.Contains(strings.ToLower(err.Error()), "unique") {
		return ErrHostnameInUse
	}
	return err
}

func scanSite(row interface{ Scan(...any) error }) (domain.PublishedSite, error) {
	var site domain.PublishedSite
	var expires sql.NullTime
	err := row.Scan(&site.ID, &site.APIKeyID, &site.Hostname, &site.CreatedAt, &expires, &site.SourceID, &site.ContentID)
	if expires.Valid {
		site.ExpiresAt = &expires.Time
	}
	return site, err
}

func (s *Store) FindPublishedSite(ctx context.Context, host string) (domain.PublishedSite, error) {
	return scanSite(s.db.QueryRowContext(ctx, `SELECT s.id, s.api_key_id, s.hostname, s.created_at, s.expires_at, s.source_id, s.content_id
		FROM published_sites s JOIN api_keys k ON k.id = s.api_key_id
		WHERE s.hostname = ? AND k.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > ?)`, host, time.Now().UTC()))
}

// ListPublishedSites includes expired sites so maintenance can retry disk cleanup.
// An empty key is reserved for server maintenance and lists all owners.
func (s *Store) ListPublishedSites(ctx context.Context, key string) ([]domain.PublishedSite, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, api_key_id, hostname, created_at, expires_at, source_id, content_id FROM published_sites WHERE (? = '' OR api_key_id = ?) ORDER BY created_at, id`, key, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	sites := []domain.PublishedSite{}
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		sites = append(sites, site)
	}
	return sites, rows.Err()
}

func (s *Store) ReplacePublishedSite(ctx context.Context, site domain.PublishedSite) error {
	return s.withSerializedWrite(ctx, func() error {
		result, err := s.db.ExecContext(ctx, `UPDATE published_sites SET content_id = ?, source_id = ?, expires_at = ? WHERE id = ? AND api_key_id = ? AND hostname = ?`, site.ContentID, site.SourceID, site.ExpiresAt, site.ID, site.APIKeyID, site.Hostname)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		return nil
	})
}

func (s *Store) DeletePublishedSite(ctx context.Context, key, id string) error {
	return s.withSerializedWrite(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		result, err := tx.ExecContext(ctx, `DELETE FROM published_sites WHERE id = ? AND api_key_id = ?`, id, key)
		if err != nil {
			return err
		}
		if n, _ := result.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM domains WHERE id = ? AND type = 'published_site'`, id); err != nil {
			return err
		}
		return tx.Commit()
	})
}
