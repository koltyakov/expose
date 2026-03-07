package client

import (
	"strings"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func websocketPath(open *tunnelproto.WSOpen) string {
	if open == nil {
		return ""
	}
	wsPath := open.Path
	if open.Query != "" {
		wsPath += "?" + open.Query
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

	fp := visitorFingerprint(open.Headers)
	if fp != "" {
		c.log.Info("forwarded websocket opened", "stream_id", streamID, "path", wsPath, "client_fingerprint", fp)
		return
	}
	c.log.Info("forwarded websocket opened", "stream_id", streamID, "path", wsPath)
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
