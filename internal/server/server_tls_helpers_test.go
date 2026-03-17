package server

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/config"

	"golang.org/x/crypto/acme/autocert"
)

func TestStaticCertificateSupportsHostAndSelection(t *testing.T) {
	t.Parallel()

	certFile, keyFile := writeTLSKeyPairFiles(t, selfSignedCertForLoopback(t))
	srv := &Server{
		cfg: config.ServerConfig{
			BaseDomain:   "localhost",
			CertCacheDir: t.TempDir(),
			TLSCertFile:  certFile,
			TLSKeyFile:   keyFile,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	staticCert, err := srv.loadStaticCertificate("auto")
	if err != nil {
		t.Fatalf("loadStaticCertificate() error = %v", err)
	}
	if staticCert == nil {
		t.Fatal("expected static certificate")
	}
	if !staticCert.supportsHost("") || !staticCert.supportsHost("localhost") {
		t.Fatal("expected certificate to support localhost")
	}
	if staticCert.supportsHost("example.com") {
		t.Fatal("expected certificate to reject unrelated host")
	}
	if !(&staticCertificate{}).supportsHost("anything") {
		t.Fatal("expected leaf-less static certificate to accept host checks")
	}

	getCert := srv.selectCertificate(nil, staticCert, tlsModeWildcard)
	if cert, err := getCert(&tls.ClientHelloInfo{ServerName: "localhost"}); err != nil || cert == nil {
		t.Fatalf("selectCertificate(static) = (%v, %v)", cert, err)
	}

	if _, err := srv.selectCertificate(nil, nil, tlsModeDynamic)(&tls.ClientHelloInfo{ServerName: "localhost"}); err == nil {
		t.Fatal("expected dynamic mode without manager to fail")
	}
	if _, err := srv.selectCertificate(&autocert.Manager{}, nil, tlsModeWildcard)(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("expected wildcard mode without SNI host to fail")
	}
}

func TestTLSHelperUtilities(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !fileExists(file) {
		t.Fatal("expected fileExists(file) to be true")
	}
	if fileExists(dir) || fileExists("   ") {
		t.Fatal("expected directories and blank paths to be false")
	}
	if normalizeTLSMode("") != tlsModeAuto || normalizeTLSMode(" WILDCARD ") != tlsModeWildcard {
		t.Fatal("normalizeTLSMode() mismatch")
	}

	srv := &Server{cfg: config.ServerConfig{BaseDomain: "example.com"}}
	guide := srv.wildcardSetupGuide("/tmp/wildcard.crt", "/tmp/wildcard.key")
	for _, want := range []string{"example.com", "*.example.com", "/tmp/wildcard.crt", "/tmp/wildcard.key"} {
		if !strings.Contains(guide, want) {
			t.Fatalf("wildcardSetupGuide() missing %q", want)
		}
	}
}

func TestHTTPSErrorLogWriter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	writer := newHTTPSErrorLogWriter(logger, true)

	if n, err := writer.Write([]byte("plain server error\n")); err != nil || n == 0 {
		t.Fatalf("Write(plain) = (%d, %v)", n, err)
	}
	if !strings.Contains(buf.String(), "https server error") {
		t.Fatalf("expected plain error log, got %q", buf.String())
	}

	buf.Reset()
	if !writer.logTLSHandshakeLine("http: TLS handshake error from 127.0.0.1:1234: bad certificate") {
		t.Fatal("expected TLS handshake line to be handled")
	}
	if !strings.Contains(buf.String(), "certificate provisioning in progress") {
		t.Fatalf("expected provisioning hint, got %q", buf.String())
	}

	buf.Reset()
	if !writer.logTLSHandshakeLine("http: TLS handshake error from scanner: EOF") {
		t.Fatal("expected scanner TLS line to be handled")
	}
	if !strings.Contains(buf.String(), "tls handshake rejected") {
		t.Fatalf("expected scanner rejection log, got %q", buf.String())
	}

	if writer.logTLSHandshakeLine("not a handshake line") {
		t.Fatal("expected unrelated line to be ignored")
	}
}
