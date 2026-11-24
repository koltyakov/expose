package client

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

// slowReader hands out at most chunk bytes per Read and pauses before each,
// like a frame trickling in across what used to be the idle read deadline.
type slowReader struct {
	data  []byte
	chunk int
	pause time.Duration
}

func (r *slowReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	time.Sleep(r.pause)
	n := min(len(p), r.chunk, len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestWorkerStreamReadKeepsSlowFramesInSync(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		var buf bytes.Buffer
		write := tunnelproto.WriteStreamJSON
		if v2 {
			write = tunnelproto.WriteStreamJSONV2
		}
		first := tunnelproto.Message{Kind: tunnelproto.KindRequest, Request: &tunnelproto.HTTPRequest{ID: "req-1", Method: "GET", Path: "/slow"}}
		if err := write(&buf, first); err != nil {
			t.Fatal(err)
		}
		if err := write(&buf, tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
			t.Fatal(err)
		}
		r := &slowReader{data: buf.Bytes(), chunk: 3, pause: time.Millisecond}
		got, err := readStreamMessage(r, v2)
		if err != nil {
			t.Fatalf("v2=%v: first frame: %v", v2, err)
		}
		if got.Kind != tunnelproto.KindRequest || got.Request == nil || got.Request.ID != "req-1" || got.Request.Path != "/slow" {
			t.Fatalf("v2=%v: first frame decoded as %+v", v2, got)
		}
		got, err = readStreamMessage(r, v2)
		if err != nil || got.Kind != tunnelproto.KindPing {
			t.Fatalf("v2=%v: stream desynchronized after a slow frame: %+v, %v", v2, got, err)
		}
	}
}
