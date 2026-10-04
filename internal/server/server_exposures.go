package server

import (
	"context"
	"net"
	"net/http"

	"github.com/koltyakov/expose/internal/domain"
)

type exposureStore interface {
	ListExposures(context.Context, string) ([]domain.Exposure, error)
}

func (s *Server) handleExposures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.allowPreAuthRequest(w, r) {
		return
	}
	keyID, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st, ok := s.store.(exposureStore)
	if !ok {
		http.Error(w, "exposure listing unavailable", http.StatusServiceUnavailable)
		return
	}
	exposures, err := st.ListExposures(r.Context(), keyID)
	if err != nil {
		s.log.Error("failed to list exposures", "err", err)
		http.Error(w, "failed to list exposures", http.StatusInternalServerError)
		return
	}
	port := authorityPort(r.Host)
	for i := range exposures {
		host := exposures[i].Hostname
		if port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		exposures[i].URL = "https://" + host
	}
	writeJSON(w, http.StatusOK, exposures)
}
