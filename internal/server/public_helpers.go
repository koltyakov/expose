package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

func (s *Server) resolvePublicRoute(ctx context.Context, host string) (liveRouteSnapshot, error) {
	if snap, ok := s.liveRoutes.lookupHost(host); ok {
		return snap, nil
	}
	if route, found, cached := s.routes.lookup(host); cached && found {
		return liveRouteSnapshot{route: route}, nil
	} else if cached {
		return liveRouteSnapshot{}, sql.ErrNoRows
	}
	snap, err := s.liveRoutes.upsertFromStore(ctx, s.store, host)
	if err != nil {
		return liveRouteSnapshot{}, err
	}
	return snap, nil
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
	return s.publicLimiter.allow(publicRateLimitKey(route.Domain.Hostname, clientIPFromRemoteAddr(r.RemoteAddr)))
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
	injectForwardedProxyHeaders(requestHeaders, r)
	injectForwardedFor(requestHeaders, r.RemoteAddr)

	pending := acquirePendingRequest()
	defer releasePendingRequest(pending)
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
	w.WriteHeader(resp.Status)
	if resp.Streamed {
		bodyCh, doneCh := pending.bodyStream()
		if !s.writeStreamedResponseBody(w, r, bodyCh, doneCh, s.cfg.RequestTimeout) {
			s.abortPendingRequest(sess, reqID)
		}
	} else {
		b, err := resp.Payload()
		if err == nil && len(b) > 0 {
			_, _ = w.Write(b)
		}
	}
	s.queueDomainTouch(route.Domain.ID)
}

func (s *Server) abortPendingRequest(sess *session, reqID string) {
	if sess == nil || strings.TrimSpace(reqID) == "" {
		return
	}
	if pending, ok := sess.pendingDelete(reqID); ok {
		sess.releasePending()
		pending.abort()
	}
	_ = sess.cancelRequest(reqID)
}

func publicRouteLookupErrorStatus(err error) (int, string) {
	if errors.Is(err, sql.ErrNoRows) {
		return http.StatusNotFound, "unknown host"
	}
	return http.StatusInternalServerError, "internal error"
}
