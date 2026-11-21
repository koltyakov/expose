package turnrelay

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/pion/logging"
)

type logFactory struct{ logger *slog.Logger }

func (f logFactory) NewLogger(scope string) logging.LeveledLogger {
	logger := f.logger
	if logger == nil {
		logger = slog.Default()
	}
	return relayLog{logger.With("component", "turn", "scope", scope)}
}

type relayLog struct{ *slog.Logger }

func (l relayLog) Debug(msg string) { l.Logger.Debug(msg) }
func (l relayLog) Info(msg string)  { l.Logger.Info(msg) }
func (l relayLog) Warn(msg string)  { l.Logger.Warn(msg) }
func (l relayLog) Error(msg string) {
	if isPeerCloseNoise(msg) {
		l.Logger.Debug(msg)
		return
	}
	l.Logger.Error(msg)
}
func (l relayLog) Trace(msg string)                  { l.Debug(msg) }
func (l relayLog) Tracef(format string, args ...any) { l.Debugf(format, args...) }

// Debugf is called by pion for individual datagrams, so skip formatting when
// debug output is disabled.
func (l relayLog) Debugf(format string, args ...any) {
	if !l.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	l.Debug(fmt.Sprintf(format, args...))
}
func (l relayLog) Infof(format string, args ...any)  { l.Info(fmt.Sprintf(format, args...)) }
func (l relayLog) Warnf(format string, args ...any)  { l.Warn(fmt.Sprintf(format, args...)) }
func (l relayLog) Errorf(format string, args ...any) { l.Error(fmt.Sprintf(format, args...)) }

// isPeerCloseNoise matches pion errors raised while closing a connection the
// peer already dropped, typically a port scanner on the TURN TLS listener.
// The connection is closed regardless, so these are not server faults.
func isPeerCloseNoise(msg string) bool {
	if !strings.HasPrefix(msg, "Failed to close conn") {
		return false
	}
	return strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "failed to send closeNotify")
}
