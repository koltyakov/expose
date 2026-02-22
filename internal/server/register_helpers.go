package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/domain"
)

var errRegisterSwapInactive = errors.New("register swap inactive tunnel session")

type preparedRegisterRequest struct {
	request             registerRequest
	accessUser          string
	passwordHash        string
	autoStableSubdomain bool
	clientMachineID     string
}

func (s *Server) parseAndValidateRegisterRequest(w http.ResponseWriter, r *http.Request) (preparedRegisterRequest, bool) {
	var req registerRequest
	if err := decodeJSONBody(w, r, maxRegisterBodyBytes, &req); err != nil {
		if isBodyTooLargeError(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return preparedRegisterRequest{}, false
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return preparedRegisterRequest{}, false
	}

	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "" {
		req.Mode = "temporary"
	}
	if req.Mode != "temporary" && req.Mode != "permanent" {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return preparedRegisterRequest{}, false
	}
	if req.Mode == "permanent" && req.Subdomain == "" {
		http.Error(w, "permanent mode requires subdomain", http.StatusBadRequest)
		return preparedRegisterRequest{}, false
	}

	req.User = strings.TrimSpace(req.User)
	if req.User == "" {
		req.User = "admin"
	}
	if len(req.User) > 64 {
		http.Error(w, "user must be at most 64 characters", http.StatusBadRequest)
		return preparedRegisterRequest{}, false
	}

	req.Password = strings.TrimSpace(req.Password)
	if len(req.Password) > 256 {
		http.Error(w, "password must be at most 256 characters", http.StatusBadRequest)
		return preparedRegisterRequest{}, false
	}

	accessUser := ""
	passwordHash := ""
	if req.Password != "" {
		accessUser = req.User
		hashed, hashErr := auth.HashPassword(req.Password)
		if hashErr != nil {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return preparedRegisterRequest{}, false
		}
		passwordHash = hashed
	}

	autoStableSubdomain := false
	if req.Mode == "temporary" && strings.TrimSpace(req.Subdomain) == "" && !s.wildcardTLSOn {
		if stable := stableTemporarySubdomain(req.ClientHostname, req.LocalPort); stable != "" {
			req.Subdomain = stable
			autoStableSubdomain = true
		}
	}

	return preparedRegisterRequest{
		request:             req,
		accessUser:          accessUser,
		passwordHash:        passwordHash,
		autoStableSubdomain: autoStableSubdomain,
		clientMachineID:     normalizedClientMachineID(req.ClientMachineID, req.ClientHostname),
	}, true
}

func (s *Server) allocateRegisterRoute(ctx context.Context, keyID string, prepared preparedRegisterRequest) (domain.Domain, domain.Tunnel, error) {
	req := prepared.request

	domainRec, tunnelRec, err := s.store.AllocateDomainAndTunnelWithClientMeta(
		ctx,
		keyID,
		req.Mode,
		req.Subdomain,
		s.cfg.BaseDomain,
		prepared.clientMachineID,
	)
	if isHostnameInUseError(err) {
		if swappedDomain, swappedTunnel, swapped, swapErr := s.trySwapInactiveClientSession(ctx, keyID, req.Subdomain, prepared.clientMachineID); swapErr != nil {
			if s.log != nil {
				s.log.Error("failed to swap inactive tunnel session", "subdomain", req.Subdomain, "err", swapErr)
			}
			return domain.Domain{}, domain.Tunnel{}, errors.Join(errRegisterSwapInactive, swapErr)
		} else if swapped {
			domainRec = swappedDomain
			tunnelRec = swappedTunnel
			err = nil
		}
	}
	if prepared.autoStableSubdomain && isHostnameInUseError(err) {
		// Only fall back to a random subdomain for cross-key hash collisions.
		// If the same API key already owns this subdomain with an active
		// tunnel, the client is trying to duplicate an existing session from
		// the same machine+port - block it instead of silently assigning a
		// new random subdomain.
		host := req.Subdomain + "." + normalizeHost(s.cfg.BaseDomain)
		if route, routeErr := s.store.FindRouteByHost(ctx, host); routeErr != nil || route.Domain.APIKeyID != keyID {
			domainRec, tunnelRec, err = s.store.AllocateDomainAndTunnelWithClientMeta(
				ctx,
				keyID,
				req.Mode,
				"",
				s.cfg.BaseDomain,
				prepared.clientMachineID,
			)
		}
	}
	return domainRec, tunnelRec, err
}

func (s *Server) registerURLs(hostHeader, hostname, token string) (publicURL, wsURL string) {
	wsAuthority := registrationWSAuthority(hostHeader, normalizeHost(s.cfg.BaseDomain))
	publicURL = "https://" + hostname
	if port := authorityPort(wsAuthority); port != "" && port != "443" {
		publicURL = fmt.Sprintf("https://%s:%s", hostname, port)
	}
	wsURL = fmt.Sprintf("wss://%s/v1/tunnels/connect?token=%s", wsAuthority, token)
	return publicURL, wsURL
}
