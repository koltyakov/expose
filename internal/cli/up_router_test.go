package cli

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStartUpLocalRouterConfiguresDedicatedProxyResources(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

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

func TestRewriteUpstreamRawPath(t *testing.T) {
	if got := rewriteUpstreamRawPath("/api/files/a%2Fb", "/api", true); got != "/files/a%2Fb" {
		t.Fatalf("rewrite escaped child: got %q", got)
	}
	if got := rewriteUpstreamRawPath("/api", "/api", true); got != "/" {
		t.Fatalf("rewrite exact escaped path: got %q", got)
	}
	if got := rewriteUpstreamRawPath("/api%20space/users", "/api space", true); got != "/users" {
		t.Fatalf("rewrite escaped prefix: got %q", got)
	}
	if got := rewriteUpstreamRawPath("/apiv2/files/a%2Fb", "/api", true); got != "/apiv2/files/a%2Fb" {
		t.Fatalf("rewrite non-match should be unchanged, got %q", got)
	}
}

func TestStartUpLocalRouterRewritesProxyRequests(t *testing.T) {
	type receivedRequest struct {
		path     string
		rawPath  string
		rawQuery string
		host     string
		xff      string
		xfHost   string
		xfProto  string
		public   string
		mount    string
	}

	reqs := make(chan receivedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs <- receivedRequest{
			path:     r.URL.Path,
			rawPath:  r.URL.RawPath,
			rawQuery: r.URL.RawQuery,
			host:     r.Host,
			xff:      r.Header.Get("X-Forwarded-For"),
			xfHost:   r.Header.Get("X-Forwarded-Host"),
			xfProto:  r.Header.Get("X-Forwarded-Proto"),
			public:   r.Header.Get(upRoutePublicPathHeader),
			mount:    r.Header.Get(upRouteMountPrefixHeader),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamAddr, ok := upstream.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected upstream addr type %T", upstream.Listener.Addr())
	}

	ctx := t.Context()

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
	if got.rawPath != "" {
		t.Fatalf("unexpected upstream raw path %q", got.rawPath)
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
	if got.public != "/api/users" {
		t.Fatalf("unexpected public path header %q", got.public)
	}
	if got.mount != "/api" {
		t.Fatalf("unexpected mount prefix header %q", got.mount)
	}
}

func TestStartUpLocalRouterPreservesEscapedPath(t *testing.T) {
	t.Parallel()

	reqs := make(chan struct {
		path        string
		rawPath     string
		escapedPath string
		requestURI  string
	}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs <- struct {
			path        string
			rawPath     string
			escapedPath string
			requestURI  string
		}{
			path:        r.URL.Path,
			rawPath:     r.URL.RawPath,
			escapedPath: r.URL.EscapedPath(),
			requestURI:  r.RequestURI,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	upstreamAddr, ok := upstream.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected upstream addr type %T", upstream.Listener.Addr())
	}

	router, port, err := startUpLocalRouter(t.Context(), []upLocalRoute{{
		Name:        "files",
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

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/files/a%%2Fb", port))
	if err != nil {
		t.Fatalf("GET escaped path route: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}

	got := <-reqs
	if got.path != "/files/a/b" {
		t.Fatalf("unexpected decoded upstream path %q", got.path)
	}
	if got.rawPath != "/files/a%2Fb" {
		t.Fatalf("expected raw upstream path to preserve escapes, got %q", got.rawPath)
	}
	if got.escapedPath != "/files/a%2Fb" {
		t.Fatalf("expected escaped upstream path to preserve escapes, got %q", got.escapedPath)
	}
	if got.requestURI != "/files/a%2Fb" {
		t.Fatalf("expected upstream request URI to preserve escapes, got %q", got.requestURI)
	}
}

func TestStartUpLocalRouterPrefersLongestPathPrefix(t *testing.T) {
	t.Parallel()

	rootReqs := make(chan string, 1)
	rootUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rootReqs <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer rootUpstream.Close()

	adminReqs := make(chan string, 1)
	adminUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminReqs <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer adminUpstream.Close()

	rootAddr, ok := rootUpstream.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected root upstream addr type %T", rootUpstream.Listener.Addr())
	}
	adminAddr, ok := adminUpstream.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected admin upstream addr type %T", adminUpstream.Listener.Addr())
	}

	router, port, err := startUpLocalRouter(t.Context(), []upLocalRoute{
		{
			Name:        "api",
			PathPrefix:  "/api",
			StripPrefix: true,
			LocalPort:   rootAddr.Port,
		},
		{
			Name:        "admin",
			PathPrefix:  "/api/admin",
			StripPrefix: true,
			LocalPort:   adminAddr.Port,
		},
	}, nil)
	if err != nil {
		t.Fatalf("start router: %v", err)
	}
	defer func() {
		_ = router.server.Close()
	}()

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/admin/users", port))
	if err != nil {
		t.Fatalf("GET longest path prefix route: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}

	select {
	case got := <-adminReqs:
		if got != "/users" {
			t.Fatalf("unexpected admin upstream path %q", got)
		}
	default:
		t.Fatal("expected admin upstream to receive request")
	}

	select {
	case got := <-rootReqs:
		t.Fatalf("expected shorter prefix route to be skipped, got path %q", got)
	default:
	}
}
