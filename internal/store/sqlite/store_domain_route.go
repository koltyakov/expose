package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
)

func (s *Store) FindRouteByHost(ctx context.Context, host string) (domain.TunnelRoute, error) {
	host = normalizeHostname(host)
	return s.findRoute(ctx, findRouteByHostQuery, host)
}

func (s *Store) FindRouteByTunnelID(ctx context.Context, tunnelID string) (domain.TunnelRoute, error) {
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return domain.TunnelRoute{}, sql.ErrNoRows
	}
	const query = `
SELECT
 d.id, d.api_key_id, d.type, d.hostname, d.status, d.created_at, d.last_seen_at,
 t.id, t.api_key_id, t.domain_id, t.state, t.is_temporary, t.client_meta, t.access_user, t.access_mode, t.access_password_hash, t.connected_at, t.disconnected_at
FROM tunnels t
JOIN domains d ON d.id = t.domain_id
WHERE t.id = ?
LIMIT 1`
	return s.findRoute(ctx, query, tunnelID)
}

func (s *Store) findRoute(ctx context.Context, query string, arg any) (domain.TunnelRoute, error) {
	var r domain.TunnelRoute
	var lastSeen sql.NullTime
	var connectedAt sql.NullTime
	var disconnectedAt sql.NullTime
	var clientMeta sql.NullString
	var accessUser sql.NullString
	var accessMode sql.NullString
	var accessPasswordHash sql.NullString

	stmt := s.findRouteByHostStmt
	var err error
	if stmt != nil && query == findRouteByHostQuery {
		err = stmt.QueryRowContext(ctx, arg).Scan(
			&r.Domain.ID, &r.Domain.APIKeyID, &r.Domain.Type, &r.Domain.Hostname, &r.Domain.Status, &r.Domain.CreatedAt, &lastSeen,
			&r.Tunnel.ID, &r.Tunnel.APIKeyID, &r.Tunnel.DomainID, &r.Tunnel.State, &r.Tunnel.IsTemporary, &clientMeta, &accessUser, &accessMode, &accessPasswordHash, &connectedAt, &disconnectedAt,
		)
	} else {
		err = s.db.QueryRowContext(ctx, query, arg).Scan(
			&r.Domain.ID, &r.Domain.APIKeyID, &r.Domain.Type, &r.Domain.Hostname, &r.Domain.Status, &r.Domain.CreatedAt, &lastSeen,
			&r.Tunnel.ID, &r.Tunnel.APIKeyID, &r.Tunnel.DomainID, &r.Tunnel.State, &r.Tunnel.IsTemporary, &clientMeta, &accessUser, &accessMode, &accessPasswordHash, &connectedAt, &disconnectedAt,
		)
	}
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
	if accessMode.Valid {
		r.Tunnel.AccessMode = accessMode.String
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

func (s *Store) generateSubdomain(ctx context.Context, baseDomain string) (string, error) {
	const attempts = 16
	slugs := make([]string, 0, attempts)
	hostnames := make([]any, 0, attempts)
	slugByHostname := make(map[string]struct{}, attempts)
	for range attempts {
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
