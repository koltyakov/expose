package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

type gatedUploadBody struct {
	headerSent *bool
	chunkSent  *bool
	remaining  int
	first      bool
}

func (b *gatedUploadBody) Read(p []byte) (int, error) {
	if !*b.headerSent {
		return 0, errors.New("body read before forwarding request headers")
	}
	if b.remaining == 0 {
		return 0, io.EOF
	}
	if !b.first {
		b.first = true
		p[0] = 'x'
		b.remaining--
		return 1, nil
	}
	if !*b.chunkSent {
		return 0, errors.New("first short read buffered instead of forwarded")
	}
	n := min(len(p), b.remaining)
	clear(p[:n])
	b.remaining -= n
	return n, nil
}

func (*gatedUploadBody) Close() error { return nil }

func TestUploadForwardsHeadersAndShortChunksImmediately(t *testing.T) {
	for _, length := range []int64{-1, streamingThreshold + 17} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			t.Parallel()
			var headerSent, chunkSent, ended bool
			const size = streamingThreshold + 17
			body := &gatedUploadBody{headerSent: &headerSent, chunkSent: &chunkSent, remaining: size}
			r := httptest.NewRequest(http.MethodPost, "/upload", nil)
			r.Body, r.ContentLength = body, length
			received := 0
			streamed, err := (&Server{}).sendRequestBodyWith("upload", r, nil, func(msg tunnelproto.Message) error {
				switch msg.Kind {
				case tunnelproto.KindRequest:
					headerSent = msg.Request.Streamed
				case tunnelproto.KindReqBodyEnd:
					ended = true
				}
				return nil
			}, func(chunk []byte) error {
				chunkSent = true
				received += len(chunk)
				return nil
			})
			if err != nil || !streamed || !ended || received != size {
				t.Fatalf("streamed=%t end=%t bytes=%d err=%v", streamed, ended, received, err)
			}
		})
	}
}

func TestUploadKeepsKnownSmallBodiesInline(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewBufferString("small"))
	streamed, err := (&Server{}).sendRequestBodyWith("upload", r, nil, func(msg tunnelproto.Message) error {
		if msg.Kind != tunnelproto.KindRequest || msg.Request.Streamed || string(msg.Request.Body) != "small" {
			t.Fatalf("unexpected inline message: %+v", msg)
		}
		return nil
	}, func([]byte) error { t.Fatal("small body sent as a chunk"); return nil })
	if streamed || err != nil {
		t.Fatalf("streamed=%t err=%v", streamed, err)
	}
}

func TestTruncatedUploadNeverSendsCleanBodyEnd(t *testing.T) {
	for _, length := range []int64{10, streamingThreshold + 1} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewBufferString("short"))
			r.ContentLength = length
			_, err := (&Server{}).sendRequestBodyWith("upload", r, nil, func(msg tunnelproto.Message) error {
				if msg.Kind == tunnelproto.KindReqBodyEnd {
					t.Fatal("truncated upload ended cleanly")
				}
				return nil
			}, func([]byte) error { return nil })
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated upload error=%v", err)
			}
		})
	}
}
