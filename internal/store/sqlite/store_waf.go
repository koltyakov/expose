package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/koltyakov/expose/internal/domain"
)

func (s *Store) SetTunnelWAFPathRules(ctx context.Context, tunnelID string, rules *domain.WAFPathRules) error {
	var encoded any
	if rules != nil && len(rules.IgnorePaths) > 0 {
		value, err := json.Marshal(rules.IgnorePaths)
		if err != nil {
			return err
		}
		encoded = string(value)
	}
	_, err := s.execWithSQLiteBusyRetry(ctx, `UPDATE tunnels SET waf_ignore_paths = ? WHERE id = ?`, encoded, tunnelID)
	return err
}

func decodeWAFPathRules(encoded sql.NullString, tunnel *domain.Tunnel) error {
	if tunnel == nil || !encoded.Valid || encoded.String == "" {
		return nil
	}
	var paths []string
	if err := json.Unmarshal([]byte(encoded.String), &paths); err != nil {
		return fmt.Errorf("decode tunnel WAF path rules: %w", err)
	}
	if len(paths) > 0 {
		tunnel.WAFPathRules = &domain.WAFPathRules{IgnorePaths: paths}
	}
	return nil
}
