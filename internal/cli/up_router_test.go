package cli

import "testing"

func TestUpPathPrefixMatchesSegmentAware(t *testing.T) {
	if !upPathPrefixMatches("/api", "/api") {
		t.Fatal("expected exact match")
	}
	if !upPathPrefixMatches("/api", "/api/users") {
		t.Fatal("expected child path match")
	}
	if upPathPrefixMatches("/api", "/apiv2") {
		t.Fatal("expected segment-aware non-match")
	}
	if !upPathPrefixMatches("/", "/anything") {
		t.Fatal("expected root route to match all paths")
	}
}

func TestRewriteUpstreamPath(t *testing.T) {
	if got := rewriteUpstreamPath("/api", "/api", true); got != "/" {
		t.Fatalf("rewrite exact: got %q", got)
	}
	if got := rewriteUpstreamPath("/api/users", "/api", true); got != "/users" {
		t.Fatalf("rewrite child: got %q", got)
	}
	if got := rewriteUpstreamPath("/apiv2/users", "/api", true); got != "/apiv2/users" {
		t.Fatalf("rewrite non-match should be unchanged, got %q", got)
	}
	if got := rewriteUpstreamPath("/api/users", "/api", false); got != "/api/users" {
		t.Fatalf("rewrite disabled: got %q", got)
	}
}
