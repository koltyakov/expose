package server

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

type staticCertificate struct {
	cert     tls.Certificate
	leaf     *x509.Certificate
	certFile string
	keyFile  string
}

func (s *Server) loadStaticCertificate(mode string) (*staticCertificate, error) {
	certFile := strings.TrimSpace(s.cfg.TLSCertFile)
	keyFile := strings.TrimSpace(s.cfg.TLSKeyFile)
	mode = normalizeTLSMode(mode)
	defaultCertFile := filepath.Join(s.cfg.CertCacheDir, "wildcard.crt")
	defaultKeyFile := filepath.Join(s.cfg.CertCacheDir, "wildcard.key")

	if mode == tlsModeDynamic {
		return nil, nil
	}

	if certFile == "" && keyFile == "" {
		if fileExists(defaultCertFile) && fileExists(defaultKeyFile) {
			certFile = defaultCertFile
			keyFile = defaultKeyFile
		} else {
			if mode == tlsModeWildcard {
				return nil, errors.New(s.wildcardSetupGuide(defaultCertFile, defaultKeyFile))
			}
			base := normalizeHost(s.cfg.BaseDomain)
			s.log.Info("static wildcard TLS not configured; using dynamic per-host ACME", "hint", fmt.Sprintf("to enable wildcard mode, set EXPOSE_TLS_MODE=wildcard and prepare a Let's Encrypt DNS-01 cert for %s and *.%s", base, base))
			return nil, nil
		}
	}
	if certFile == "" || keyFile == "" {
		if mode == tlsModeWildcard {
			return nil, errors.New(s.wildcardSetupGuide(defaultCertFile, defaultKeyFile))
		}
		s.log.Warn("incomplete static TLS configuration; using dynamic per-host ACME", "tls_cert_file", certFile, "tls_key_file", keyFile, "hint", "set both EXPOSE_TLS_CERT_FILE and EXPOSE_TLS_KEY_FILE")
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		if mode == tlsModeWildcard {
			return nil, fmt.Errorf("wildcard TLS mode requires a valid static certificate: %w\n\n%s", err, s.wildcardSetupGuide(defaultCertFile, defaultKeyFile))
		}
		s.log.Warn("failed to load static TLS certificate; using dynamic per-host ACME", "cert_file", certFile, "key_file", keyFile, "err", err)
		return nil, nil
	}
	var leaf *x509.Certificate
	if len(cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	base := normalizeHost(s.cfg.BaseDomain)
	if leaf != nil && mode == tlsModeWildcard {
		if err := leaf.VerifyHostname(base); err != nil {
			return nil, fmt.Errorf("wildcard TLS certificate must include %s: %w", base, err)
		}
		wildHost := "check." + base
		if err := leaf.VerifyHostname(wildHost); err != nil {
			return nil, fmt.Errorf("wildcard TLS certificate must include *.%s: %w", base, err)
		}
	}
	subject := ""
	if leaf != nil {
		subject = leaf.Subject.String()
	}
	s.log.Info("static TLS certificate loaded", "cert_file", certFile, "key_file", keyFile, "subject", subject)
	return &staticCertificate{
		cert:     cert,
		leaf:     leaf,
		certFile: certFile,
		keyFile:  keyFile,
	}, nil
}

func (s *Server) selectCertificate(manager *autocert.Manager, staticCert *staticCertificate, mode string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	mode = normalizeTLSMode(mode)
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host := normalizeHost(hello.ServerName)
		if staticCert != nil && staticCert.supportsHost(host) {
			return &staticCert.cert, nil
		}
		if mode == tlsModeWildcard {
			if host == "" {
				return nil, errors.New("wildcard TLS mode requires SNI host")
			}
			return nil, fmt.Errorf("wildcard TLS certificate does not cover host %q", host)
		}
		if manager == nil {
			return nil, errors.New("dynamic TLS is not available")
		}
		return manager.GetCertificate(hello)
	}
}

func (c *staticCertificate) supportsHost(host string) bool {
	if c == nil {
		return false
	}
	if host == "" {
		return true
	}
	if c.leaf == nil {
		return true
	}
	return c.leaf.VerifyHostname(host) == nil
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func normalizeTLSMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return tlsModeAuto
	}
	return mode
}

type httpsServerErrorLogWriter struct {
	log                  *slog.Logger
	dynamicACME          bool
	provisioningHintOnce sync.Once
}

func newHTTPSErrorLogWriter(logger *slog.Logger, dynamicACME bool) *httpsServerErrorLogWriter {
	return &httpsServerErrorLogWriter{log: logger, dynamicACME: dynamicACME}
}

func (w *httpsServerErrorLogWriter) Write(p []byte) (n int, err error) {
	line := strings.TrimSpace(string(p))
	if line == "" {
		return len(p), nil
	}
	if w.logTLSHandshakeLine(line) {
		return len(p), nil
	}
	w.log.Warn("https server error", "err", line)
	return len(p), nil
}

func (w *httpsServerErrorLogWriter) logTLSHandshakeLine(line string) bool {
	const marker = "TLS handshake error from "
	if !strings.Contains(line, marker) {
		return false
	}
	idx := strings.Index(line, marker)
	if idx < 0 {
		return false
	}
	payload := line[idx+len(marker):]
	addr, reason, ok := strings.Cut(payload, ": ")
	if !ok {
		w.log.Debug("tls handshake dropped", "detail", payload)
		return true
	}
	reason = strings.TrimSpace(reason)
	if isLikelyScannerTLSReason(reason) {
		w.log.Debug("tls handshake rejected", "remote_addr", strings.TrimSpace(addr), "reason", reason)
		return true
	}
	if w.dynamicACME && isLikelyTLSProvisioningReason(reason) {
		w.provisioningHintOnce.Do(func() {
			w.log.Info("TLS certificate provisioning in progress for a new host; initial handshake retries are expected")
		})
		w.log.Info("tls handshake retried during certificate provisioning", "remote_addr", strings.TrimSpace(addr), "reason", reason)
		return true
	}
	w.log.Warn("tls handshake failed", "remote_addr", strings.TrimSpace(addr), "reason", reason)
	return true
}

func isLikelyTLSProvisioningReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	return strings.Contains(reason, "bad certificate") ||
		strings.Contains(reason, "failed to verify certificate") ||
		strings.Contains(reason, "certificate is not standards compliant") ||
		strings.Contains(reason, "x509:")
}

func isLikelyScannerTLSReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	return reason == "eof" ||
		strings.Contains(reason, "missing server name") ||
		strings.Contains(reason, "unsupported application protocols") ||
		strings.Contains(reason, "offered only unsupported versions") ||
		strings.Contains(reason, "no cipher suite supported by both client and server") ||
		strings.Contains(reason, "unsupported sslv2 handshake received") ||
		strings.Contains(reason, "host not allowed") ||
		strings.Contains(reason, "connection reset by peer") ||
		strings.Contains(reason, "i/o timeout") ||
		strings.Contains(reason, "first record does not look like a tls handshake") ||
		strings.Contains(reason, "http request to an https server")
}

func (s *Server) wildcardSetupGuide(defaultCertFile, defaultKeyFile string) string {
	base := normalizeHost(s.cfg.BaseDomain)
	return fmt.Sprintf(`wildcard TLS mode is enabled, but wildcard certificate files are not ready.

Required certificate SANs:
  - %s
  - *.%s

Place certificate files in one of these ways:
  1) Set EXPOSE_TLS_CERT_FILE and EXPOSE_TLS_KEY_FILE
  2) Or place files at:
     cert: %s
     key:  %s

Let's Encrypt wildcard requires DNS-01 challenge (TXT records in your DNS zone).

Step-by-step (Certbot + DNS provider API):
  1) Create a DNS API token for %s with permission to edit TXT records.
  2) Install Certbot and your DNS provider plugin.
  3) Request cert for both apex and wildcard:
     certbot certonly --agree-tos --email <your-email> --non-interactive \
       --dns-<provider> --dns-<provider>-credentials <credentials-file> \
       -d %s -d '*.%s'
  4) Certbot output files are usually:
       /etc/letsencrypt/live/%s/fullchain.pem
       /etc/letsencrypt/live/%s/privkey.pem
  5) Copy/link them to:
       %s
       %s
     (or set EXPOSE_TLS_CERT_FILE / EXPOSE_TLS_KEY_FILE directly)
  6) Restart server with EXPOSE_TLS_MODE=wildcard.

Tip: use EXPOSE_TLS_MODE=auto to keep service running with dynamic per-host ACME while preparing wildcard certs.`,
		base, base, defaultCertFile, defaultKeyFile, base, base, base, base, base, defaultCertFile, defaultKeyFile)
}

func (s *Server) serverTLSMode() string {
	if s.wildcardTLSOn {
		return tlsModeWildcard
	}
	return tlsModeDynamic
}

func stableTemporarySubdomain(hostname, port string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	port = strings.TrimSpace(port)
	if hostname == "" || port == "" {
		return ""
	}
	seed := hostname + ":" + port
	sum := sha1.Sum([]byte(seed))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	enc = strings.ToLower(enc)
	const subdomainLen = 6
	if len(enc) > subdomainLen {
		enc = enc[:subdomainLen]
	}
	return enc
}
