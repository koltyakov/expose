package client

import (
	"strings"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func websocketPath(open *tunnelproto.WSOpen) string {
	if open == nil {
		return ""
	}
	wsPath := config.SanitizeTerminalString(open.Path)
	if query := strings.TrimSpace(open.Query); query != "" {
		wsPath += "?" + config.SanitizeTerminalString(query)
	}
	return wsPath
}

func websocketLogPath(open *tunnelproto.WSOpen) string {
	if open == nil {
		return ""
	}
	wsPath := config.SanitizeTerminalString(open.Path)
	if query := strings.TrimSpace(open.Query); query != "" {
		wsPath += "?" + config.RedactQueryValues(query)
	}
	return wsPath
}

func (c *Client) trackWSOpen(streamID string, open *tunnelproto.WSOpen) {
	if c == nil {
		return
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" || open == nil {
		return
	}

	wsPath := websocketPath(open)
	if c.display != nil {
		c.display.TrackWSOpen(streamID, wsPath, open.Headers)
		return
	}
	if c.log == nil {
		return
	}

	logPath := websocketLogPath(open)
	fp := visitorFingerprint(open.Headers)
	if fp != "" {
		c.log.Info("forwarded websocket opened", "stream_id", streamID, "path", logPath, "client_fingerprint", fp)
		return
	}
	c.log.Info("forwarded websocket opened", "stream_id", streamID, "path", logPath)
}

func (c *Client) trackWSClose(streamID string) {
	if c == nil {
		return
	}
	streamID = strings.TrimSpace(streamID)
	if streamID == "" {
		return
	}
	if c.display != nil {
		c.display.TrackWSClose(streamID)
		return
	}
	if c.log != nil {
		c.log.Info("forwarded websocket closed", "stream_id", streamID)
	}
}
