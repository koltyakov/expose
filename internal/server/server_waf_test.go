package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
)

func TestNormalizeWAFIgnorePaths(t *testing.T) {
	got, err := normalizeWAFIgnorePaths([]string{" /generated/assets/ ", "/generated/assets", "/cache"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/generated/assets", "/cache"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeWAFIgnorePaths() = %#v, want %#v", got, want)
	}
}

func TestNormalizeWAFIgnorePathsRejectsInvalidLocations(t *testing.T) {
	tests := []struct {
		name   string
		values []string
	}{
		{name: "relative", values: []string{"generated"}},
		{name: "dot segment", values: []string{"/generated/../secret"}},
		{name: "query", values: []string{"/generated?debug=true"}},
		{name: "too many", values: make([]string, maxWAFIgnorePaths+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeWAFIgnorePaths(tt.values); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestWAFPathIgnoredMatchesLocationBoundaries(t *testing.T) {
	prefixes := []string{"/generated/assets"}
	for _, requestPath := range []string{"/generated/assets", "/generated/assets/app.js", "/generated/assets/../assets/app.js"} {
		if !wafPathIgnored(prefixes, requestPath) {
			t.Fatalf("expected %q to match", requestPath)
		}
	}
	for _, requestPath := range []string{"/generated/asset", "/generated/assets-old/app.js"} {
		if wafPathIgnored(prefixes, requestPath) {
			t.Fatalf("expected %q not to match", requestPath)
		}
	}
}

func TestServerIgnoresOnlySensitiveRuleForTunnelLocation(t *testing.T) {
	srv := &Server{
		routes: routeCache{
			entries:       make(map[string]routeCacheEntry),
			hostsByTunnel: make(map[string]map[string]struct{}),
		},
		liveRoutes: newLiveRouteIndex(),
	}
	route := domain.TunnelRoute{
		Domain: domain.Domain{Hostname: "app.example.com"},
		Tunnel: domain.Tunnel{
			ID: "tun-1",
			WAFPathRules: &domain.WAFPathRules{
				IgnorePaths: []string{"/generated/assets"},
			},
		},
	}
	srv.routes.set("app.example.com", route)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/generated/assets/.framework/app.js", nil)
	if !srv.shouldIgnoreWAFPathRule(req, sensitiveFileProbeRule) {
		t.Fatal("expected cached tunnel location to ignore sensitive-file-probe")
	}
	srv.liveRoutes.upsert(route)
	if !srv.shouldIgnoreWAFPathRule(req, sensitiveFileProbeRule) {
		t.Fatal("expected live tunnel location to ignore sensitive-file-probe")
	}
	if srv.shouldIgnoreWAFPathRule(req, "xss") {
		t.Fatal("expected other WAF rules to remain enabled")
	}
	req.URL.Path = "/other/.framework/app.js"
	if srv.shouldIgnoreWAFPathRule(req, sensitiveFileProbeRule) {
		t.Fatal("expected path outside configured location to remain protected")
	}
	srv.liveRoutes.setRegistrationConfig("tun-1", "", "", "", &domain.WAFPathRules{IgnorePaths: []string{"/other"}})
	if !srv.shouldIgnoreWAFPathRule(req, sensitiveFileProbeRule) {
		t.Fatal("expected resumed tunnel rules to replace the live configuration")
	}
}
