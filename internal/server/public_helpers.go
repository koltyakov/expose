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
	if _, ok := s.siteHosts.Load(host); ok {
		return true
	}
	if _, ok := s.liveRoutes.lookupHost(host); ok {
		return true
	}
	if _, _, cached := s.routes.lookup(host); cached {
		return true
	}
	return s.lookupLimiter == nil || s.lookupLimiter.allow(rateLimitClientKey(s.clientIP(r)))
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
	clientIP = rateLimitClientKey(clientIP)
	if host == "" {
		host = "unknown-host"
	}
	if clientIP == "" {
		clientIP = "unknown-client"
	}
	return host + "|" + clientIP
}

// rateLimitClientKey groups IPv6 clients by /64, the smallest prefix normally
// assigned to one subscriber. Keyed by full address, one host could rotate
// through its /64 to get a fresh bucket per request, defeating every per-IP
// limit and growing limiter maps without bound.
func rateLimitClientKey(clientIP string) string {
	clientIP = strings.TrimSpace(clientIP)
	addr, err := netip.ParseAddr(clientIP)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return clientIP
	}
	prefix, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return clientIP
	}
	return prefix.String()
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
	reqID := s.nextRequestID()
	if !sess.tryAcquirePending(maxPendingPerSessionFor(s.cfg)) {
		s.writePublicRejection(w, r, http.StatusServiceUnavailable, "tunnel overloaded", rejectionConcurrency)
		return
	}

	requestHeaders := tunnelproto.ShallowCloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(requestHeaders)
	preparePublicAccessHeaders(requestHeaders, r, route)
	injectForwardedProxyHeaders(requestHeaders, r)
	injectForwardedFor(requestHeaders, s.clientIP(r))

	pending := newPendingRequest()
	pending.sessionBudget = &sess.queuedResponses
	pending.globalBudget = &s.queuedResponses
	sess.pendingStore(reqID, pending)
	defer func() {
		pending.finish()
		pending.discardBody()
	}()

	streamed, err := s.sendRequestHead(reqID, r, requestHeaders, sess.writeJSON)
	if err != nil {
		s.abortPendingRequest(sess, reqID)
		s.writeUploadFailure(w, r, err)
		return
	}

	// A streamed body uploads in the background, so a response the origin
	// sends before reading all of it reaches the visitor at once.
	var upload *requestUpload
	if streamed {
		upload = s.startRequestUpload(w, r, reqID, sess.writeJSON, func(payload []byte) error {
			return sess.writeBinaryFrame(tunnelproto.BinaryFrameReqBody, reqID, 0, payload)
		}, nil, func(err error) {
			if err != nil && !errors.Is(err, errUploadStopped) {
				// The origin cannot get the rest of the body. Cancel the
				// request, which also ends a response already in progress.
				s.abortPendingRequest(sess, reqID)
			}
		})
		// Runs before the pending cleanup above: the upload is joined
		// before the handler returns.
		defer upload.finish(false)
	}

	resp, ok, timedOut := s.waitPendingHeader(r.Context(), pending, upload)
	if !ok || resp == nil {
		s.abortPendingRequest(sess, reqID)
		if err := upload.failure(); err != nil {
			s.writeUploadFailure(w, r, err)
			return
		}
		if timedOut {
			http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
			return
		}
		if r.Context().Err() == nil {
			http.Error(w, "tunnel closed", http.StatusBadGateway)
		}
		return
	}
	if s.handleDelegatedAccessResponse(w, r, route, resp.Status, resp.Headers) {
		if resp.Streamed {
			s.abortPendingRequest(sess, reqID)
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
	stripUpstreamAltSvc(respHeaders)
	for k, vals := range respHeaders {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	setInlineContentLength(w, r, resp, upload)
	w.WriteHeader(normalizeUpstreamStatus(resp.Status))
	if resp.Streamed {
		// Send headers now: a stream such as server-sent events may not
		// produce its first chunk for a while.
		flushResponse(w)
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
	finishUploadAfterResponse(w, r, normalizeUpstreamStatus(resp.Status), upload)
	s.queueDomainTouch(route.Domain.ID)
}

// finishUploadAfterResponse stops an upload still running after the final
// response, flushing first so the visitor is not kept waiting by the drain.
func finishUploadAfterResponse(w http.ResponseWriter, r *http.Request, status int, upload *requestUpload) {
	if upload == nil {
		return
	}
	select {
	case <-upload.doneCh():
		return
	default:
	}
	flushResponse(w)
	upload.finish(drainUploadOnFinish(w, r, status))
}

// waitPendingHeader waits for the response header. While a streamed upload
// runs, the wait is bounded only by the visitor; RequestTimeout starts when
// the upload ends, as it did when uploads completed before the wait.
func (s *Server) waitPendingHeader(ctx context.Context, pending *pendingRequest, upload *requestUpload) (resp *tunnelproto.HTTPResponse, ok, timedOut bool) {
	if upload != nil {
		select {
		case resp := <-pending.headerCh:
			return resp, resp != nil, false
		case <-pending.doneCh:
			resp, ok := pending.waitHeader(ctx)
			return resp, ok, false
		case <-ctx.Done():
			return nil, false, false
		case <-upload.doneCh():
			if upload.failure() != nil {
				return nil, false, false
			}
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	resp, ok = pending.waitHeader(waitCtx)
	if !ok && errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
		timedOut = true
	}
	return resp, ok, timedOut
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
