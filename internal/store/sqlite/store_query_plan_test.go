package sqlite

import (
	"strings"
	"testing"
	"time"
)

// TestHotQueryPlansUseIndexes pins the plans of frequent and cleanup queries
// after index changes: none may scan a whole table that has an index for its
// filter. Plans come from SQLite's planner without ANALYZE statistics, the
// state of a server database.
func TestHotQueryPlansUseIndexes(t *testing.T) {
	st, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Now().UTC()
	cases := []struct {
		name  string
		query string
		args  []any
	}{
		{"resolve api key", resolveAPIKeyIDQuery, []any{"hash"}},
		{"active tunnel count", activeTunnelCountByKeyQuery, []any{"key", "connected"}},
		{"hostname active", isHostnameActiveQuery, []any{"a.example.com", "active"}},
		{"find route", findRouteByHostQuery, []any{"a.example.com"}},
		{"purge inactive domains", purgeInactiveTunnelDomainsQuery, []any{now, 100}},
		{"list exposures", `
SELECT d.hostname FROM domains d
LEFT JOIN tunnels t ON t.id = (
	SELECT id FROM tunnels WHERE domain_id = d.id AND api_key_id = ?
	ORDER BY (state = 'connected') DESC, rowid DESC LIMIT 1
)
LEFT JOIN published_sites p ON p.id = d.id AND p.api_key_id = ?
WHERE d.api_key_id = ? AND (t.id IS NOT NULL OR p.id IS NOT NULL)
ORDER BY d.hostname`, []any{"key", "key", "key"}},
		{"permanent domain claim", `SELECT id FROM domains WHERE hostname = ? AND api_key_id = ? AND type = ?`, []any{"a.example.com", "key", "permanent_subdomain"}},
	}
	for _, tc := range cases {
		rows, err := st.db.Query("EXPLAIN QUERY PLAN "+tc.query, tc.args...)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		_ = rows.Close()
		for _, step := range plan {
			for _, table := range []string{"domains", "tunnels", "api_keys", "published_sites"} {
				full := strings.HasPrefix(step, "SCAN "+table) || strings.HasPrefix(step, "SCAN d") && table == "domains" ||
					strings.HasPrefix(step, "SCAN t") && table == "tunnels"
				if full && !strings.Contains(step, "USING") {
					t.Errorf("%s scans %s without an index:\n%s", tc.name, table, strings.Join(plan, "\n"))
				}
			}
		}
	}
}
