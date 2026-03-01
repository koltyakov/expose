package debughttp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	httppprof "net/http/pprof"
	"strings"
	"time"
)

const shutdownTimeout = 5 * time.Second

// StartPprofServer starts an optional pprof HTTP server on addr and shuts it
// down when ctx is canceled. It returns immediately after the listener is
// bound so address conflicts fail fast.
func StartPprofServer(ctx context.Context, addr string, log *slog.Logger, component string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
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

func newPprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
	return mux
}
