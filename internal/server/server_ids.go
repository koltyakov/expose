package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (s *Server) nextRequestID() string {
	b := make([]byte, 0, 32)
	b = append(b, "req_"...)
	b = strconv.AppendInt(b, time.Now().UnixNano(), 10)
	b = append(b, '_')
	b = strconv.AppendUint(b, s.requestSeq.Add(1), 10)
	return string(b)
}

func (s *Server) nextWSStreamID() string {
	b := make([]byte, 0, 32)
	b = append(b, "ws_"...)
	b = strconv.AppendInt(b, time.Now().UnixNano(), 10)
	b = append(b, '_')
	b = strconv.AppendUint(b, s.requestSeq.Add(1), 10)
	return string(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
}

func shutdownServer(server *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// waitGroupWait blocks until wg reaches zero or timeout elapses.
// Returns false if the timeout fired before all goroutines finished.
func waitGroupWait(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func normalizedClientMachineID(machineID, hostname string) string {
	if v := strings.TrimSpace(machineID); v != "" {
		return v
	}
	return strings.ToLower(strings.TrimSpace(hostname))
}

func registrationWSAuthority(hostHeader, fallbackHost string) string {
	hostHeader = strings.TrimSpace(hostHeader)
	if hostHeader == "" {
		return fallbackHost
	}
	h, port, err := net.SplitHostPort(hostHeader)
	if err == nil {
		h = normalizeHost(h)
		if h == "" {
			h = fallbackHost
		}
		if port == "" || port == "443" {
			return h
		}
		return net.JoinHostPort(h, port)
	}
	hostOnly := normalizeHost(hostHeader)
	if hostOnly != "" {
		return hostOnly
	}
	return fallbackHost
}

func authorityPort(authority string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(authority))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(port)
}
