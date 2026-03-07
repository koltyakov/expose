package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStartUpLocalRouterConfiguresDedicatedProxyResources(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router, _, err := startUpLocalRouter(ctx, []upLocalRoute{{
		Name:       "api",
		PathPrefix: "/",
		LocalPort:  8080,
	}}, nil)
	if err != nil {
		t.Fatalf("start router: %v", err)
	}
	defer func() {
		_ = router.server.Close()
	}()

	if router.tr == nil {
		t.Fatal("expected dedicated proxy transport")
	}
	if len(router.routes) != 1 || router.routes[0].proxy == nil {
		t.Fatal("expected compiled proxy route")
	}
	if router.routes[0].proxy.Transport != router.tr {
		t.Fatal("expected proxy to reuse router transport")
	}
	if router.routes[0].proxy.BufferPool == nil {
		t.Fatal("expected proxy buffer pool to be configured")
	}
	if router.tr.ResponseHeaderTimeout != upRouterProxyResponseHeaderTTL {
		t.Fatalf("expected response header timeout %s, got %s", upRouterProxyResponseHeaderTTL, router.tr.ResponseHeaderTimeout)
	}
}

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

func TestStartUpLocalRouterRewritesProxyRequests(t *testing.T) {
	type receivedRequest struct {
		path     string
		rawQuery string
		host     string
		xff      string
		xfHost   string
		xfProto  string
	}

	reqs := make(chan receivedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs <- receivedRequest{
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
			host:     r.Host,
			xff:      r.Header.Get("X-Forwarded-For"),
			xfHost:   r.Header.Get("X-Forwarded-Host"),
			xfProto:  r.Header.Get("X-Forwarded-Proto"),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamAddr, ok := upstream.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected upstream addr type %T", upstream.Listener.Addr())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	router, port, err := startUpLocalRouter(ctx, []upLocalRoute{{
		Name:        "api",
		PathPrefix:  "/api",
		StripPrefix: true,
		LocalPort:   upstreamAddr.Port,
	}}, nil)
	if err != nil {
		t.Fatalf("start router: %v", err)
	}
	defer func() {
		_ = router.server.Close()
	}()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/users?id=1", port), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = "demo.example.test"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}

	got := <-reqs
	if got.path != "/users" {
		t.Fatalf("unexpected upstream path %q", got.path)
	}
	if got.rawQuery != "id=1" {
		t.Fatalf("unexpected upstream query %q", got.rawQuery)
	}
	if got.host != "demo.example.test" {
		t.Fatalf("unexpected upstream host %q", got.host)
	}
	if got.xff == "" {
		t.Fatal("expected X-Forwarded-For header")
	}
	if got.xfHost != "demo.example.test" {
		t.Fatalf("unexpected X-Forwarded-Host %q", got.xfHost)
	}
	if got.xfProto != "http" {
		t.Fatalf("unexpected X-Forwarded-Proto %q", got.xfProto)
	}
}
