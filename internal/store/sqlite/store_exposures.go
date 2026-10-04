package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

// ListExposures returns one summary per owned hostname, including retained
// disconnected reservations and expired sites awaiting cleanup. An empty key
// never grants access to other owners.
func (s *Store) ListExposures(ctx context.Context, keyID string) ([]domain.Exposure, error) {
	// Prefer a connected tunnel, otherwise the latest registration. Tunnel IDs
	// are random and connected_at is NULL for registrations that never connected.
	rows, err := s.db.QueryContext(ctx, `
SELECT d.hostname, d.type, d.created_at, t.id, t.state, p.id, p.expires_at
FROM domains d
LEFT JOIN tunnels t ON t.id = (
	SELECT id FROM tunnels
	WHERE domain_id = d.id AND api_key_id = ?
	ORDER BY (state = 'connected') DESC, rowid DESC
	LIMIT 1
)
LEFT JOIN published_sites p ON p.id = d.id AND p.api_key_id = ?
WHERE d.api_key_id = ? AND (t.id IS NOT NULL OR p.id IS NOT NULL)
ORDER BY d.hostname`, keyID, keyID, keyID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	exposures := []domain.Exposure{}
	now := time.Now().UTC()
	for rows.Next() {
		var e domain.Exposure
		var domainType string
		var tunnelID, state, siteID sql.NullString
		var expires sql.NullTime
		if err := rows.Scan(&e.Hostname, &domainType, &e.CreatedAt, &tunnelID, &state, &siteID, &expires); err != nil {
			return nil, err
		}
		if siteID.Valid {
			e.ID, e.Type, e.Status = siteID.String, domain.ExposureTypeSite, "active"
			if expires.Valid {
				e.ExpiresAt = &expires.Time
				if !expires.Time.After(now) {
					e.Status = "expired"
				}
			}
		} else {
			e.ID, e.Type, e.Status = tunnelID.String, domain.ExposureTypeTunnel, state.String
			e.Temporary = domainType == domain.DomainTypeTemporarySubdomain
		}
		exposures = append(exposures, e)
	}
	return exposures, rows.Err()
}
