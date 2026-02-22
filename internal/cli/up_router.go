package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"
)

const upRouterShutdownTimeout = 5 * time.Second

type upLocalRoute struct {
	Name        string
	Subdomain   string
	PathPrefix  string
	StripPrefix bool
	LocalPort   int
	proxy       *httputil.ReverseProxy
}

type upLocalRouter struct {
	ln     net.Listener
	server *http.Server
	routes []upLocalRoute
	log    *slog.Logger
}

func startUpLocalRouter(ctx context.Context, routes []upLocalRoute, log *slog.Logger) (*upLocalRouter, int, error) {
	if len(routes) == 0 {
		return nil, 0, errors.New("no routes configured")
	}
	compiled := make([]upLocalRoute, 0, len(routes))
	for _, r := range routes {
		target, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", r.LocalPort))
		if err != nil {
			return nil, 0, fmt.Errorf("build target for %s: %w", r.Name, err)
		}
		routeCopy := r
		proxy := httputil.NewSingleHostReverseProxy(target)
		origDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			originalPath := req.URL.Path
			origDirector(req)
			req.URL.Path = rewriteUpstreamPath(originalPath, routeCopy.PathPrefix, routeCopy.StripPrefix)
			req.URL.RawPath = ""
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
			if log != nil {
				log.Warn("local route proxy error", "route", routeCopy.Name, "path_prefix", routeCopy.PathPrefix, "upstream_port", routeCopy.LocalPort, "err", err)
			}
			http.Error(w, "local upstream unavailable", http.StatusBadGateway)
		}
		routeCopy.proxy = proxy
		compiled = append(compiled, routeCopy)
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		if len(compiled[i].PathPrefix) == len(compiled[j].PathPrefix) {
			return compiled[i].Name < compiled[j].Name
		}
		return len(compiled[i].PathPrefix) > len(compiled[j].PathPrefix)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}

	rt := &upLocalRouter{
		ln:     ln,
		routes: compiled,
		log:    log,
	}
	rt.server = &http.Server{Handler: rt}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), upRouterShutdownTimeout)
		defer cancel()
		_ = rt.server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := rt.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && log != nil {
			log.Error("up local router stopped", "err", err)
		}
	}()

	addr, _ := ln.Addr().(*net.TCPAddr)
	if addr == nil {
		return rt, 0, nil
	}
	return rt, addr.Port, nil
}

func (r *upLocalRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r == nil || len(r.routes) == 0 {
		http.Error(w, "no local routes configured", http.StatusServiceUnavailable)
		return
	}
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	for _, route := range r.routes {
		if upPathPrefixMatches(route.PathPrefix, path) {
			route.proxy.ServeHTTP(w, req)
			return
		}
	}
	http.NotFound(w, req)
}

func upPathPrefixMatches(prefix, path string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

func rewriteUpstreamPath(path, prefix string, strip bool) string {
	if path == "" {
		path = "/"
	}
	if !strip || prefix == "" || prefix == "/" {
		return path
	}
	if path == prefix {
		return "/"
	}
	if strings.HasPrefix(path, prefix+"/") {
		out := strings.TrimPrefix(path, prefix)
		if out == "" {
			return "/"
		}
		if !strings.HasPrefix(out, "/") {
			out = "/" + out
		}
		return out
	}
	return path
}
