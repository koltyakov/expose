package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestEmptyHTTP2RequestDoesNotStreamUpload(t *testing.T) {
	srv := &Server{}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Body == nil || r.Body == http.NoBody || r.ContentLength != 0 {
			t.Errorf("expected the HTTP/2 non-nil empty body: proto=%s length=%d body=%T", r.Proto, r.ContentLength, r.Body)
		}
		var messages []tunnelproto.Message
		streamed, err := srv.sendRequestBodyWith("empty", r, nil, func(msg tunnelproto.Message) error {
			messages = append(messages, msg)
			return nil
		}, func([]byte) error {
			t.Error("empty request sent a body frame")
			return nil
		})
		if err != nil || streamed || len(messages) != 1 || messages[0].Request == nil || messages[0].Request.Streamed {
			t.Errorf("empty request created an upload stream: streamed=%t messages=%+v err=%v", streamed, messages, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	c := upstream.Client()
	c.Timeout = time.Second
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		req, err := http.NewRequestWithContext(t.Context(), method, upstream.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
