package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

func (s *Server) resolvePublicRoute(ctx context.Context, host string) (liveRouteSnapshot, error) {
	if snap, ok := s.liveRoutes.lookupHost(host); ok {
		s.routeCacheHits.Add(1)
		return snap, nil
	}
	if route, found, cached := s.routes.lookup(host); cached && found {
		s.routeCacheHits.Add(1)
		return liveRouteSnapshot{route: route}, nil
	} else if cached {
		s.routeCacheHits.Add(1)
		return liveRouteSnapshot{}, sql.ErrNoRows
	}
	s.routeCacheMisses.Add(1)
	return s.routeLookups.do(ctx, host, func() (liveRouteSnapshot, error) {
		if snap, ok := s.liveRoutes.lookupHost(host); ok {
			return snap, nil
		}
		if route, found, cached := s.routes.lookup(host); cached && found {
			return liveRouteSnapshot{route: route}, nil
		} else if cached {
			return liveRouteSnapshot{}, sql.ErrNoRows
		}
		for attempt := 0; attempt < 2; attempt++ {
			version := s.routeVersions.current(host)
			s.routeStoreLoads.Add(1)
			lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durationOr(s.cfg.RequestTimeout, 30*time.Second))
			route, err := s.store.FindRouteByHost(lookupCtx, host)
			cancel()
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					if s.publishRouteMiss(host, version) {
						return liveRouteSnapshot{}, err
					}
					if snap, ok := s.liveRoutes.lookupHost(host); ok {
						return snap, nil
					}
					continue
				}
				return liveRouteSnapshot{}, err
			}
			snap, published := s.publishResolvedRoute(host, version, route)
			if published || snap.route.Domain.ID != "" {
				return snap, nil
			}
		}
		return s.resolvePublicRouteStable(ctx, host)
	})
}

func (s *Server) resolvePublicRouteStable(ctx context.Context, host string) (liveRouteSnapshot, error) {
	shard := s.routeVersions.shard(normalizeHost(host))
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if snap, ok := s.liveRoutes.lookupHost(host); ok {
		return snap, nil
	}
	if route, found, cached := s.routes.lookup(host); cached && found {
		return liveRouteSnapshot{route: route}, nil
	} else if cached {
		return liveRouteSnapshot{}, sql.ErrNoRows
	}
	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durationOr(s.cfg.RequestTimeout, 30*time.Second))
	defer cancel()
	s.routeStoreLoads.Add(1)
	route, err := s.store.FindRouteByHost(lookupCtx, host)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.routes.setMiss(host)
		}
		return liveRouteSnapshot{}, err
	}
	s.routes.set(host, route)
	return liveRouteSnapshot{route: route}, nil
}

func (s *Server) allowPublicRouteLookup(host string, r *http.Request) bool {
	if _, ok := s.liveRoutes.lookupHost(host); ok {
		return true
	}
	if _, _, cached := s.routes.lookup(host); cached {
		return true
	}
	return s.lookupLimiter == nil || s.lookupLimiter.allow(s.clientIP(r))
}

func (s *Server) resolvePublicSession(snap liveRouteSnapshot) (*session, int, string, bool) {
	if snap.session == nil && strings.TrimSpace(snap.route.Tunnel.ID) != "" {
		s.hub.mu.RLock()
		snap.session = s.hub.sessions[snap.route.Tunnel.ID]
		s.hub.mu.RUnlock()
	}
	if snap.session != nil && (snap.active || snap.route.Tunnel.State == domain.TunnelStateConnected) {
		return snap.session, 0, "", true
	}
	if !snap.route.Tunnel.IsTemporary {
		return nil, http.StatusServiceUnavailable, "tunnel offline", false
	}
	return nil, http.StatusNotFound, "unknown host", false
}

func (s *Server) allowPublicRequest(route domain.TunnelRoute, r *http.Request) bool {
	if s.publicLimiter == nil {
		return true
	}
	return s.publicLimiter.allow(publicRateLimitKey(route.Domain.Hostname, s.clientIP(r)))
}

func publicRateLimitKey(host, clientIP string) string {
	host = normalizeHost(host)
	clientIP = strings.TrimSpace(clientIP)
	if host == "" {
		host = "unknown-host"
	}
	if clientIP == "" {
		clientIP = "unknown-client"
	}
	return host + "|" + clientIP
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	return netutil.NormalizeHost(remoteAddr)
}

// clientIP resolves the client address used for rate-limit keys. When the
// direct peer falls inside a configured trusted proxy CIDR, the client is
// taken from X-Forwarded-For (rightmost untrusted hop); otherwise the header
// is ignored so direct clients cannot spoof their rate-limit identity.
func (s *Server) clientIP(r *http.Request) string {
	remote := clientIPFromRemoteAddr(r.RemoteAddr)
	if len(s.trustedProxies) == 0 {
		return remote
	}
	remoteIP, err := netip.ParseAddr(remote)
	if err != nil || !ipInTrustedProxies(remoteIP, s.trustedProxies) {
		return remote
	}
	// Join every X-Forwarded-For header, not just the first: a client can
	// send several, and a proxy that forwards them verbatim instead of
	// collapsing them would otherwise leave the trusted-hop walk running
	// over an entirely client-controlled header.
	if forwarded := clientIPFromXFF(strings.Join(r.Header.Values("X-Forwarded-For"), ","), s.trustedProxies); forwarded != "" {
		return forwarded
	}
	return remote
}

func ipInTrustedProxies(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIPFromXFF walks X-Forwarded-For right to left and returns the first
// hop that is not itself a trusted proxy: trusted proxies append the real
// peer address to the right, so client-supplied spoofed entries on the left
// are never selected. If every hop is trusted, the leftmost (closest to the
// original client) is returned. A malformed hop fails closed to "" so the
// caller falls back to the direct peer address.
func clientIPFromXFF(xff string, trusted []netip.Prefix) string {
	parts := strings.Split(xff, ",")
	leftmost := ""
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if part == "" {
			continue
		}
		ip, err := netip.ParseAddr(part)
		if err != nil {
			return ""
		}
		if !ipInTrustedProxies(ip, trusted) {
			return ip.String()
		}
		leftmost = ip.String()
	}
	return leftmost
}

func (s *Server) proxyPublicHTTP(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	if s.cfg.MaxBodyBytes > 0 && r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	}

	reqID := s.nextRequestID()
	if !sess.tryAcquirePending(maxPendingPerSessionFor(s.cfg)) {
		http.Error(w, "tunnel overloaded", http.StatusServiceUnavailable)
		return
	}

	requestHeaders := tunnelproto.ShallowCloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(requestHeaders)
	stripPublicAccessCookie(requestHeaders)
	stripPublicAccessCredentials(requestHeaders, route)
	injectForwardedProxyHeaders(requestHeaders, r)
	injectForwardedFor(requestHeaders, r.RemoteAddr)

	pending := newPendingRequest()
	sess.pendingStore(reqID, pending)

	if _, err := s.sendRequestBody(sess, reqID, r, requestHeaders); err != nil {
		s.abortPendingRequest(sess, reqID)
		if isBodyTooLargeError(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else if errors.Is(err, tunneltransport.ErrWritePumpBackpressure) {
			http.Error(w, "tunnel overloaded", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "tunnel write failed", http.StatusBadGateway)
		}
		return
	}

	waitCtx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()

	resp, ok := pending.waitHeader(waitCtx)
	if !ok || resp == nil {
		if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
			s.abortPendingRequest(sess, reqID)
			http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
			return
		}
		s.abortPendingRequest(sess, reqID)
		if r.Context().Err() == nil {
			http.Error(w, "tunnel closed", http.StatusBadGateway)
		}
		return
	}
	if shouldServeFallbackFavicon(r, resp.Status) {
		if resp.Streamed {
			s.abortPendingRequest(sess, reqID)
		}
		writeFallbackFavicon(w, r)
		s.queueDomainTouch(route.Domain.ID)
		return
	}
	respHeaders := resp.Headers
	netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
	for k, vals := range respHeaders {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(normalizeUpstreamStatus(resp.Status))
	if resp.Streamed {
		if !s.writeStreamedResponseBody(w, r, pending, s.cfg.RequestTimeout) {
			s.abortPendingRequest(sess, reqID)
			if r.Context().Err() == nil {
				// The body is truncated and the status line already went out.
				// Abort the connection so the visitor sees a failed transfer
				// instead of a silently incomplete response.
				panic(http.ErrAbortHandler)
			}
		}
	} else {
		b, err := resp.Payload()
		if err == nil && len(b) > 0 {
			_, _ = w.Write(b)
		}
	}
	s.queueDomainTouch(route.Domain.ID)
}

func normalizeUpstreamStatus(status int) int {
	if status < http.StatusOK || status > 599 {
		return http.StatusBadGateway
	}
	return status
}

func (s *Server) abortPendingRequest(sess *session, reqID string) {
	if sess == nil || strings.TrimSpace(reqID) == "" {
		return
	}
	if pending, ok := sess.pendingDelete(reqID); ok {
		sess.releasePending()
		pending.abort()
		pending.discardBody()
	}
	_ = sess.cancelRequest(reqID)
}

func publicRouteLookupErrorStatus(err error) (int, string) {
	if errors.Is(err, sql.ErrNoRows) {
		return http.StatusNotFound, "unknown host"
	}
	return http.StatusInternalServerError, "internal error"
}
