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
	"sync"
	"time"
)

const (
	upRouterShutdownTimeout        = 5 * time.Second
	upRouterProxyBufferSize        = 32 * 1024
	upRouterProxyIdleConnTimeout   = 90 * time.Second
	upRouterProxyResponseHeaderTTL = 2 * time.Minute
	upRoutePublicPathHeader        = "X-Expose-Public-Path"
	upRouteMountPrefixHeader       = "X-Expose-Mount-Prefix"
)

type upLocalRoute struct {
	Name        string
	Subdomain   string
	PathPrefix  string
	StripPrefix bool
	LocalPort   int
	StaticDir   string
	proxy       *httputil.ReverseProxy
}

type upLocalRouter struct {
	ln     net.Listener
	server *http.Server
	routes []upLocalRoute
	log    *slog.Logger
	tr     *http.Transport
}

func startUpLocalRouter(ctx context.Context, routes []upLocalRoute, log *slog.Logger) (*upLocalRouter, int, error) {
	if len(routes) == 0 {
		return nil, 0, errors.New("no routes configured")
	}
	transport := newUpRouterTransport(len(routes))
	compiled := make([]upLocalRoute, 0, len(routes))
	for _, r := range routes {
		target, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", r.LocalPort))
		if err != nil {
			return nil, 0, fmt.Errorf("build target for %s: %w", r.Name, err)
		}
		routeCopy := r
		proxy := &httputil.ReverseProxy{
			Rewrite: func(preq *httputil.ProxyRequest) {
				preq.SetURL(target)
				preq.Out.Host = preq.In.Host
				preq.SetXForwarded()
				preq.Out.Header.Set(upRoutePublicPathHeader, preq.In.URL.Path)
				if routeCopy.StripPrefix && routeCopy.PathPrefix != "" && routeCopy.PathPrefix != "/" {
					preq.Out.Header.Set(upRouteMountPrefixHeader, routeCopy.PathPrefix)
				} else {
					preq.Out.Header.Del(upRouteMountPrefixHeader)
				}
				preq.Out.URL.Path = rewriteUpstreamPath(preq.In.URL.Path, routeCopy.PathPrefix, routeCopy.StripPrefix)
				preq.Out.URL.RawPath = ""
			},
			Transport:  transport,
			BufferPool: upRouterProxyBufferPool,
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
		tr:     transport,
	}
	rt.server = &http.Server{Handler: rt}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), upRouterShutdownTimeout)
		defer cancel()
		_ = rt.server.Shutdown(shutdownCtx)
	}()
	go func() {
		defer transport.CloseIdleConnections()
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

func newUpRouterTransport(routeCount int) *http.Transport {
	base, _ := http.DefaultTransport.(*http.Transport)
	tr := base.Clone()
	maxPerHost := max(16, routeCount*8)
	tr.MaxIdleConns = maxPerHost
	tr.MaxIdleConnsPerHost = maxPerHost
	tr.MaxConnsPerHost = maxPerHost
	tr.IdleConnTimeout = upRouterProxyIdleConnTimeout
	tr.ResponseHeaderTimeout = upRouterProxyResponseHeaderTTL
	return tr
}

type upRouterBufferPoolType struct {
	pool sync.Pool
}

var upRouterProxyBufferPool = &upRouterBufferPoolType{
	pool: sync.Pool{
		New: func() any {
			buf := make([]byte, upRouterProxyBufferSize)
			return &buf
		},
	},
}

func (p *upRouterBufferPoolType) Get() []byte {
	buf := p.pool.Get().(*[]byte)
	return (*buf)[:upRouterProxyBufferSize]
}

func (p *upRouterBufferPoolType) Put(buf []byte) {
	if cap(buf) < upRouterProxyBufferSize {
		return
	}
	buf = buf[:upRouterProxyBufferSize]
	p.pool.Put(&buf)
}
