package debughttp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	httppprof "net/http/pprof"
	"os"
	"strings"
	"time"
)

const shutdownTimeout = 5 * time.Second

// allowRemoteEnv opts in to binding the pprof server on a non-loopback
// address. pprof exposes heap contents, goroutine stacks, and CPU profiles
// with no authentication, so a public bind must be an explicit decision.
const allowRemoteEnv = "EXPOSE_PPROF_ALLOW_REMOTE"

// StartPprofServer starts an optional pprof HTTP server on addr and shuts it
// down when ctx is canceled. It returns immediately after the listener is
// bound so address conflicts fail fast. Non-loopback addresses are refused
// unless EXPOSE_PPROF_ALLOW_REMOTE=true.
func StartPprofServer(ctx context.Context, addr string, log *slog.Logger, component string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if err := checkLoopbackBind(addr); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           newPprofMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		if log != nil {
			log.Info("pprof listening", "component", strings.TrimSpace(component), "addr", ln.Addr().String())
		}
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && log != nil {
			log.Error("pprof server error", "component", strings.TrimSpace(component), "err", err)
		}
	}()

	return nil
}

// checkLoopbackBind refuses non-loopback pprof listen addresses unless the
// operator explicitly opted in via EXPOSE_PPROF_ALLOW_REMOTE=true.
func checkLoopbackBind(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// A bare port like ":6060" fails SplitHostPort only for malformed
		// input; net.Listen will surface that. Addresses of the form
		// ":6060" split successfully with an empty host.
		return fmt.Errorf("invalid pprof listen address %q: %w", addr, err)
	}

	if isLoopbackHost(host) {
		return nil
	}
	if allowRemotePprof() {
		return nil
	}
	return fmt.Errorf(
		"refusing to serve pprof on non-loopback address %q: pprof exposes heap and stack data without authentication; bind to 127.0.0.1 or set %s=true to override",
		addr, allowRemoteEnv,
	)
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func allowRemotePprof() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(allowRemoteEnv))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func newPprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
	return mux
}
