package turnrelay

import (
	"fmt"
	"log/slog"

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

func (l relayLog) Debug(msg string)                  { l.Logger.Debug(msg) }
func (l relayLog) Info(msg string)                   { l.Logger.Info(msg) }
func (l relayLog) Warn(msg string)                   { l.Logger.Warn(msg) }
func (l relayLog) Error(msg string)                  { l.Logger.Error(msg) }
func (l relayLog) Trace(msg string)                  { l.Debug(msg) }
func (l relayLog) Tracef(format string, args ...any) { l.Debug(fmt.Sprintf(format, args...)) }
func (l relayLog) Debugf(format string, args ...any) { l.Debug(fmt.Sprintf(format, args...)) }
func (l relayLog) Infof(format string, args ...any)  { l.Info(fmt.Sprintf(format, args...)) }
func (l relayLog) Warnf(format string, args ...any)  { l.Warn(fmt.Sprintf(format, args...)) }
func (l relayLog) Errorf(format string, args ...any) { l.Error(fmt.Sprintf(format, args...)) }
