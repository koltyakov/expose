package server

import (
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

// takeOverHTTP3Stream sends the pending response header and takes over the
// HTTP/3 stream. Since quic-go v0.66, HTTPStream no longer flushes the header
// itself and writes to the stream fail until it has been sent.
func takeOverHTTP3Stream(w http.ResponseWriter, streamer http3.HTTPStreamer) (*http3.Stream, error) {
	if err := http.NewResponseController(w).Flush(); err != nil {
		return nil, err
	}
	return streamer.HTTPStream(), nil
}
