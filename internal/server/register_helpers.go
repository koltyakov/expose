package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/domain"
)

type preparedRegisterRequest struct {
	request             registerRequest
	accessUser          string
	accessMode          string
	passwordHash        string
	autoStableSubdomain bool
	clientMachineID     string
}

func reuseStableAccessPasswordHash(prepared *preparedRegisterRequest, existing domain.TunnelRoute, keyID string) {
	if prepared == nil {
		return
	}
	if prepared.request.Password == "" || prepared.passwordHash == "" {
		return
	}
	if strings.TrimSpace(existing.Domain.APIKeyID) != strings.TrimSpace(keyID) {
		return
	}

	existingHash := strings.TrimSpace(existing.Tunnel.AccessPasswordHash)
	if existingHash == "" {
		return
	}
	if publicAccessExpectedUser(existing) != prepared.accessUser {
		return
	}
	if publicAccessMode(existing) != prepared.accessMode {
		return
	}
	if !auth.VerifyPasswordHash(existingHash, prepared.request.Password) {
		return
	}

	prepared.passwordHash = existingHash
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
	mode, err := access.NormalizeMode(req.AccessMode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return preparedRegisterRequest{}, false
	}
	req.AccessMode = mode
	if req.Password != "" && req.AccessMode == "" {
		req.AccessMode = access.ModeForm
	}
	if req.AccessMode != "" && req.Password == "" {
		http.Error(w, "protect mode requires password", http.StatusBadRequest)
		return preparedRegisterRequest{}, false
	}

	accessUser := ""
	accessMode := ""
	passwordHash := ""
	if req.Password != "" {
		accessUser = req.User
		accessMode = req.AccessMode
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
		accessMode:          accessMode,
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

func (s *Server) tryResumeRegisterRoute(
	ctx context.Context,
	keyID string,
	prepared preparedRegisterRequest,
	resumeTunnelID string,
) (domain.Domain, domain.Tunnel, bool, error) {
	resumeTunnelID = strings.TrimSpace(resumeTunnelID)
	if resumeTunnelID != "" {
		domainRec, tunnelRec, err := s.store.ResumeTunnelSession(ctx, resumeTunnelID, keyID, prepared.clientMachineID)
		if err == nil {
			if s.log != nil {
				s.log.Info("tunnel session resumed", "tunnel_id", tunnelRec.ID, "hostname", domainRec.Hostname, "source", "header")
			}
			return domainRec, tunnelRec, true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) && !isHostnameInUseError(err) {
			return domain.Domain{}, domain.Tunnel{}, false, err
		}
	}

	subdomain := strings.TrimSpace(prepared.request.Subdomain)
	if subdomain == "" || prepared.clientMachineID == "" {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}

	host := strings.ToLower(strings.TrimSpace(subdomain)) + "." + normalizeHost(s.cfg.BaseDomain)
	route, err := s.store.FindRouteByHost(ctx, host)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, false, err
	}
	if route.Domain.APIKeyID != keyID || route.Tunnel.State == domain.TunnelStateClosed {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}

	existingMachineID := strings.TrimSpace(route.Tunnel.ClientMeta)
	if existingMachineID != "" && existingMachineID != prepared.clientMachineID {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}

	domainRec, tunnelRec, err := s.store.ResumeTunnelSession(ctx, route.Tunnel.ID, keyID, prepared.clientMachineID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isHostnameInUseError(err) {
			return domain.Domain{}, domain.Tunnel{}, false, nil
		}
		return domain.Domain{}, domain.Tunnel{}, false, err
	}
	if s.log != nil {
		s.log.Info("tunnel session resumed", "tunnel_id", tunnelRec.ID, "hostname", domainRec.Hostname, "source", "hostname")
	}
	return domainRec, tunnelRec, true, nil
}

func (s *Server) registerURLs(hostHeader, hostname, token string) (publicURL, wsURL, h3URL string) {
	wsAuthority := registrationWSAuthority(hostHeader, normalizeHost(s.cfg.BaseDomain))
	publicURL = "https://" + hostname
	if port := authorityPort(wsAuthority); port != "" && port != "443" {
		publicURL = fmt.Sprintf("https://%s:%s", hostname, port)
	}
	wsURL = fmt.Sprintf("wss://%s/v1/tunnels/connect?token=%s", wsAuthority, token)
	h3URL = fmt.Sprintf("https://%s/v1/tunnels/connect-h3?token=%s", wsAuthority, token)
	return publicURL, wsURL, h3URL
}
