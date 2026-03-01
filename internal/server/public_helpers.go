package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func (s *Server) resolvePublicRoute(ctx context.Context, host string) (domain.TunnelRoute, error) {
	route, found, cached := s.routes.lookup(host)
	if cached {
		if found {
			return route, nil
		}
		return domain.TunnelRoute{}, sql.ErrNoRows
	}

	route, err := s.store.FindRouteByHost(ctx, host)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.routes.setMiss(host)
		}
		return domain.TunnelRoute{}, err
	}
	s.routes.set(host, route)
	return route, nil
}

func (s *Server) resolvePublicSession(route domain.TunnelRoute) (*session, int, string, bool) {
	s.hub.mu.RLock()
	sess := s.hub.sessions[route.Tunnel.ID]
	s.hub.mu.RUnlock()
	if sess != nil && route.Tunnel.State == domain.TunnelStateConnected {
		return sess, 0, "", true
	}
	if !route.Tunnel.IsTemporary {
		return nil, http.StatusServiceUnavailable, "tunnel offline", false
	}
	return nil, http.StatusNotFound, "unknown host", false
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

	requestHeaders := tunnelproto.CloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(requestHeaders)
	stripPublicAccessCookie(requestHeaders)
	injectForwardedProxyHeaders(requestHeaders, r)
	injectForwardedFor(requestHeaders, r.RemoteAddr)

	respCh := make(chan tunnelproto.Message, streamingChanSize)
	sess.pendingStore(reqID, respCh)

	if _, err := s.sendRequestBody(sess, reqID, r, requestHeaders); err != nil {
		s.abortPendingRequest(sess, reqID, respCh)
		if isBodyTooLargeError(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "tunnel write failed", http.StatusBadGateway)
		}
		return
	}

	timer := time.NewTimer(s.cfg.RequestTimeout)
	stopTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	defer stopTimer()

	select {
	case msg, ok := <-respCh:
		if !ok || msg.Kind != tunnelproto.KindResponse || msg.Response == nil {
			http.Error(w, "tunnel closed", http.StatusBadGateway)
			return
		}
		resp := msg.Response
		respHeaders := tunnelproto.CloneHeaders(resp.Headers)
		netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
		for k, vals := range respHeaders {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.Status)
		if resp.Streamed {
			if !s.writeStreamedResponseBody(w, r, respCh, s.cfg.RequestTimeout) {
				s.abortPendingRequest(sess, reqID, respCh)
			}
		} else {
			b, err := tunnelproto.DecodeBody(resp.BodyB64)
			if err == nil && len(b) > 0 {
				_, _ = w.Write(b)
			}
		}
		s.queueDomainTouch(route.Domain.ID)
	case <-timer.C:
		s.abortPendingRequest(sess, reqID, respCh)
		http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
	case <-r.Context().Done():
		s.abortPendingRequest(sess, reqID, respCh)
	}
}

func (s *Server) abortPendingRequest(sess *session, reqID string, respCh chan tunnelproto.Message) {
	if sess == nil || strings.TrimSpace(reqID) == "" {
		return
	}
	if sess.pendingDelete(reqID) {
		sess.releasePending()
		if respCh != nil {
			close(respCh)
		}
	}
	_ = sess.cancelRequest(reqID)
}

func publicRouteLookupErrorStatus(err error) (int, string) {
	if errors.Is(err, sql.ErrNoRows) {
		return http.StatusNotFound, "unknown host"
	}
	return http.StatusInternalServerError, "internal error"
}
