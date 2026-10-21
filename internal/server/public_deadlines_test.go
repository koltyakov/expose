package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicDeadlinesBoundImplicitBodyDrains(t *testing.T) {
	for _, operation := range []string{"write", "flush", "close", "buffered"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			done := make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				if _, err := io.ReadFull(r.Body, make([]byte, 1)); err != nil {
					return
				}
				switch operation {
				case "write":
					_, _ = io.WriteString(w, strings.Repeat("response", 1024))
				case "flush":
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
				case "close":
					_ = r.Body.Close()
				default:
					_, _ = io.WriteString(w, "ok")
				}
			})
			const timeout = 100 * time.Millisecond
			server := httptest.NewServer(requestReadDeadlineMiddleware(publicDeadlineMiddleware(handler, timeout, time.Second), timeout))
			defer server.Close()
			conn, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			// Keep the socket open while withholding nine declared body bytes.
			_, _ = fmt.Fprint(conn, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nx")
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("implicit body drain exceeded the server deadline")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("handler remained blocked on an implicit body drain")
			}
		})
	}
}

func TestPublicDeadlinesAllowActiveTransfers(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, upload := range []bool{false, true} {
			t.Run(fmt.Sprintf("h2=%t/upload=%t", h2, upload), func(t *testing.T) {
				t.Parallel()
				const timeout = 100 * time.Millisecond
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if upload {
						body, err := io.ReadAll(r.Body)
						if err != nil {
							http.Error(w, err.Error(), http.StatusRequestTimeout)
							return
						}
						_, _ = w.Write(body)
						return
					}
					for range 16 {
						_, _ = io.WriteString(w, "x")
						w.(http.Flusher).Flush()
						time.Sleep(25 * time.Millisecond)
					}
				})
				server := httptest.NewUnstartedServer(requestReadDeadlineMiddleware(publicDeadlineMiddleware(handler, timeout, timeout), timeout))
				server.Config.ReadTimeout = timeout
				server.Config.WriteTimeout = timeout
				server.EnableHTTP2 = h2
				server.StartTLS()
				defer server.Close()
				var body io.Reader
				if upload {
					reader, writer := io.Pipe()
					defer func() { _ = reader.Close() }()
					body = reader
					go func() {
						defer func() { _ = writer.Close() }()
						for range 16 {
							if _, err := io.WriteString(writer, "x"); err != nil {
								return
							}
							time.Sleep(25 * time.Millisecond)
						}
					}()
				}
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/transfer", body)
				client := server.Client()
				client.Timeout = 3 * time.Second
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				data, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != http.StatusOK || string(data) != strings.Repeat("x", 16) {
					t.Fatalf("active transfer failed: status=%d data=%q err=%v", resp.StatusCode, data, err)
				}
				if h2 && resp.ProtoMajor != 2 {
					t.Fatalf("expected HTTP/2, got %s", resp.Proto)
				}
			})
		}
	}
}

func TestPublicDeadlinesPreserveServiceWriter(t *testing.T) {
	w := &fakeHTTP3ResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	publicDeadlineMiddleware(http.HandlerFunc(func(got http.ResponseWriter, _ *http.Request) {
		if got != w {
			t.Fatal("service writer was wrapped; HTTP/3 takeover would be hidden")
		}
	}), time.Second, time.Second).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/_expose/v1/tunnels/connect-h3", nil))
}

type deadlineConnectionWriter struct {
	net.Conn
	header http.Header
}

func (w *deadlineConnectionWriter) Header() http.Header { return w.header }
func (*deadlineConnectionWriter) WriteHeader(int)       {}

func TestPublicDeadlinesStillBoundBlockedIO(t *testing.T) {
	for _, reading := range []bool{true, false} {
		t.Run(fmt.Sprint(reading), func(t *testing.T) {
			t.Parallel()
			conn, peer := net.Pipe()
			defer func() { _ = conn.Close(); _ = peer.Close() }()
			w := &deadlineConnectionWriter{Conn: conn, header: make(http.Header)}
			r := httptest.NewRequest(http.MethodPost, "/blocked", nil)
			r.Body = conn
			var blockedErr error
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if reading {
					_, blockedErr = r.Body.Read(make([]byte, 1))
				} else {
					_, blockedErr = w.Write([]byte("blocked"))
				}
			})
			started := time.Now()
			publicDeadlineMiddleware(handler, 50*time.Millisecond, 50*time.Millisecond).ServeHTTP(w, r)
			if blockedErr == nil || time.Since(started) > time.Second {
				t.Fatalf("blocked operation escaped its deadline: %v", blockedErr)
			}
			if timeout, ok := blockedErr.(net.Error); !ok || !timeout.Timeout() {
				t.Fatalf("expected a timeout, got %v", blockedErr)
			}
		})
	}
}
