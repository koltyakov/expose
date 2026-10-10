package server

import "net/http"

func (s *Server) handleTURNCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.allowPreAuthRequest(w, r) {
		return
	}
	keyID, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.turn == nil {
		http.Error(w, "TURN relay is disabled", http.StatusServiceUnavailable)
		return
	}
	// Reuse registration's per-key limiter to bound credential issuance as well
	// as the existing per-IP limiter protecting authentication lookups.
	if s.regLimiter != nil && !s.regLimiter.allow(keyID) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	credentials, err := s.turn.Credentials(keyID)
	if err != nil {
		s.log.Error("failed to issue TURN credentials", "err", err)
		http.Error(w, "failed to issue TURN credentials", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, credentials)
}
