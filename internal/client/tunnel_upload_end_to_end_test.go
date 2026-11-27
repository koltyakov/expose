package client

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// publicUploadClients returns the HTTP/2 client the tunnel fixture uses and an
// HTTP/1.1-only client, whose server-side writer and drain rules differ.
func publicUploadClients(h *endToEndTunnel) map[string]*http.Client {
	h1 := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return map[string]*http.Client{
		"h2":   h.client,
		"h1.1": {Transport: h1, Timeout: 5 * time.Second},
	}
}

func (h *endToEndTunnel) assertHealthy(t *testing.T, client *http.Client) {
	t.Helper()
	// Several requests cycle through pooled HTTP/3 workers, so a worker left
	// misaligned by the upload would surface here.
	for i := range 6 {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, h.url+"/ready", nil)
		req.Host = "bench.example.com"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("follow-up request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ready" {
			t.Fatalf("follow-up request %d: status=%d body=%q", i, resp.StatusCode, body)
		}
	}
}

// An origin may answer before the upload ends. The final response must reach
// the visitor while the visitor still holds the body open.
func TestTunnelEndToEndEarlyResponseDuringOpenUpload(t *testing.T) {
	const firstPart = 32 << 10
	for _, transport := range []string{"ws", "quic"} {
		t.Run(transport, func(t *testing.T) {
			h := newEndToEndTunnel(t, transport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// A net/http HTTP/1 origin otherwise withholds its response
				// while it discards the unread body.
				_ = http.NewResponseController(w).EnableFullDuplex()
				if _, err := io.ReadFull(r.Body, make([]byte, firstPart)); err != nil {
					t.Errorf("origin read: %v", err)
				}
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = io.WriteString(w, "too large")
				w.(http.Flusher).Flush()
			}), 2*time.Second)
			for name, client := range publicUploadClients(h) {
				t.Run(name, func(t *testing.T) {
					pr, pw := io.Pipe()
					defer func() { _ = pw.Close() }()
					go func() { _, _ = pw.Write(bytes.Repeat([]byte("u"), firstPart)) }()
					req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.url+"/upload", pr)
					req.Host = "bench.example.com"
					type result struct {
						status int
						body   string
						err    error
					}
					got := make(chan result, 1)
					go func() {
						resp, err := client.Do(req)
						if err != nil {
							got <- result{err: err}
							return
						}
						body, err := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						got <- result{status: resp.StatusCode, body: string(body), err: err}
					}()
					select {
					case res := <-got:
						if res.err != nil || res.status != http.StatusRequestEntityTooLarge || res.body != "too large" {
							t.Fatalf("early response: status=%d body=%q err=%v", res.status, res.body, res.err)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("early response was held until the upload ended")
					}
					_ = pw.Close()
					h.assertHealthy(t, client)
				})
			}
		})
	}
}

// A full-duplex origin streams its 200 while it still reads a valid upload.
// Response headers must not cut the upload short.
func TestTunnelEndToEndFullDuplexStreamKeepsUpload(t *testing.T) {
	const rounds = 4
	for _, transport := range []string{"ws", "quic"} {
		t.Run(transport, func(t *testing.T) {
			h := newEndToEndTunnel(t, transport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = http.NewResponseController(w).EnableFullDuplex()
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				buf := make([]byte, 32<<10)
				for {
					n, err := r.Body.Read(buf)
					if n > 0 {
						_, _ = w.Write(bytes.ToUpper(buf[:n]))
						w.(http.Flusher).Flush()
					}
					if err != nil {
						_, _ = io.WriteString(w, "|end")
						return
					}
				}
			}), 2*time.Second)
			for name, client := range publicUploadClients(h) {
				t.Run(name, func(t *testing.T) {
					pr, pw := io.Pipe()
					defer func() { _ = pw.Close() }()
					req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, h.url+"/echo", pr)
					req.Host = "bench.example.com"
					respCh := make(chan *http.Response, 1)
					errCh := make(chan error, 1)
					go func() {
						resp, err := client.Do(req)
						if err != nil {
							errCh <- err
							return
						}
						respCh <- resp
					}()
					// The WAF previews the first 16 KiB before proxying, so lead
					// with more than that.
					lead := bytes.Repeat([]byte("x"), 20<<10)
					go func() { _, _ = pw.Write(lead) }()
					var resp *http.Response
					select {
					case resp = <-respCh:
					case err := <-errCh:
						t.Fatal(err)
					case <-time.After(3 * time.Second):
						t.Fatal("no response headers during the upload")
					}
					defer func() { _ = resp.Body.Close() }()
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status %d", resp.StatusCode)
					}
					leadEcho := make([]byte, len(lead))
					if _, err := io.ReadFull(resp.Body, leadEcho); err != nil || !bytes.Equal(leadEcho, bytes.ToUpper(lead)) {
						t.Fatalf("lead echo err=%v", err)
					}
					echo := make([]byte, 4)
					for i := range rounds {
						if _, err := pw.Write([]byte("abcd")); err != nil {
							t.Fatal(err)
						}
						if _, err := io.ReadFull(resp.Body, echo); err != nil || string(echo) != "ABCD" {
							t.Fatalf("round %d echo=%q err=%v", i, echo, err)
						}
					}
					_ = pw.Close()
					rest, err := io.ReadAll(resp.Body)
					if err != nil || string(rest) != "|end" {
						t.Fatalf("stream end=%q err=%v", rest, err)
					}
					h.assertHealthy(t, client)
				})
			}
		})
	}
}

// An HTTP/1.1 visitor that finishes its upload within the drain window after
// a delimited early response keeps its keep-alive connection.
func TestTunnelEndToEndEarlyResponseDrainKeepsHTTP1Connection(t *testing.T) {
	const firstPart = 32 << 10
	for _, transport := range []string{"ws", "quic"} {
		t.Run(transport, func(t *testing.T) {
			h := newEndToEndTunnel(t, transport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = http.NewResponseController(w).EnableFullDuplex()
				if r.Method == http.MethodPost {
					_, _ = io.ReadFull(r.Body, make([]byte, firstPart))
				}
				w.Header().Set("Content-Length", "9")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = io.WriteString(w, "too large")
			}), 2*time.Second)
			client := publicUploadClients(h)["h1.1"]
			var conns []net.Conn
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { conns = append(conns, info.Conn) }}
			pr, pw := io.Pipe()
			go func() { _, _ = pw.Write(bytes.Repeat([]byte("u"), firstPart)) }()
			req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodPost, h.url+"/upload", pr)
			req.Host = "bench.example.com"
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			// Finish the upload after the response is out but well inside the
			// drain window. The transport reuses a connection only once its
			// request write has finished.
			time.Sleep(100 * time.Millisecond)
			_, _ = pw.Write(bytes.Repeat([]byte("v"), 8<<10))
			_ = pw.Close()
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge || string(body) != "too large" {
				t.Fatalf("status=%d body=%q err=%v", resp.StatusCode, body, err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				next, _ := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, h.url+"/ready", nil)
				next.Host = "bench.example.com"
				conns = conns[:1]
				resp, err := client.Do(next)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if len(conns) == 2 && conns[1] == conns[0] {
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("the drained HTTP/1.1 connection was not reused")
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

// The origin closes a public websocket while the visitor keeps sending. The
// server relay stops with a write to the tunnel still in flight; it must
// join that writer before closing the stream, and the tunnel stays healthy.
func TestTunnelEndToEndWebSocketCloseDuringVisitorWrites(t *testing.T) {
	for _, transport := range []string{"ws", "quic"} {
		t.Run(transport, func(t *testing.T) {
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			h := newEndToEndTunnel(t, transport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				for range 8 {
					if _, _, err := conn.ReadMessage(); err != nil {
						return
					}
				}
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "bye"), time.Now().Add(time.Second))
			}), 2*time.Second)
			dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 5 * time.Second}
			for round := range 5 {
				header := http.Header{"Host": {"bench.example.com"}}
				conn, resp, err := dialer.DialContext(t.Context(), "wss"+strings.TrimPrefix(h.url, "https")+"/ws", header)
				if err != nil {
					t.Fatalf("round %d dial: %v (resp=%v)", round, err, resp)
				}
				payload := bytes.Repeat([]byte("w"), 4<<10)
				closed := make(chan struct{})
				go func() {
					defer close(closed)
					for {
						if _, _, err := conn.ReadMessage(); err != nil {
							return
						}
					}
				}()
				for {
					_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
					if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
						break
					}
					select {
					case <-closed:
					default:
						continue
					}
					break
				}
				_ = conn.Close()
				<-closed
			}
			h.assertHealthy(t, h.client)
		})
	}
}
