package server

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/koltyakov/expose/internal/netutil"
)

func normalizeHost(host string) string {
	return netutil.NormalizeHost(host)
}

// injectForwardedFor appends the client's IP to the X-Forwarded-For header
// chain so the tunnel client can identify unique callers.
func injectForwardedFor(h map[string][]string, remoteAddr string) {
	ip := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		ip = host
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	existing := getAndNormalizeForwardedFor(h)
	if existing != "" {
		h["X-Forwarded-For"] = []string{existing + ", " + ip}
	} else {
		h["X-Forwarded-For"] = []string{ip}
	}
}

// getAndNormalizeForwardedFor returns the first X-Forwarded-For header value
// and canonicalizes the header key in-place.
func getAndNormalizeForwardedFor(h map[string][]string) string {
	if h == nil {
		return ""
	}
	if vals, ok := h["X-Forwarded-For"]; ok {
		if len(vals) == 0 {
			return ""
		}
		return strings.TrimSpace(vals[0])
	}
	var existing string
	for k, vals := range h {
		if !strings.EqualFold(k, "X-Forwarded-For") {
			continue
		}
		if existing == "" && len(vals) > 0 {
			existing = strings.TrimSpace(vals[0])
		}
		delete(h, k)
	}
	return existing
}

// injectForwardedProxyHeaders overwrites reverse-proxy headers to reflect the
// public request. Public callers can spoof these headers, so we remove any
// case-insensitive variants before setting canonical keys.
func injectForwardedProxyHeaders(h map[string][]string, r *http.Request) {
	if h == nil || r == nil {
		return
	}

	host := strings.TrimSpace(r.Host)
	if host == "" {
		return
	}

	deleteHeaderCI(h, "Host")
	deleteHeaderCI(h, "X-Forwarded-Proto")
	deleteHeaderCI(h, "X-Forwarded-Host")
	deleteHeaderCI(h, "X-Forwarded-Port")

	h["Host"] = []string{host}

	proto := "http"
	defaultPort := "80"
	if r.TLS != nil {
		proto = "https"
		defaultPort = "443"
	}

	h["X-Forwarded-Proto"] = []string{proto}
	h["X-Forwarded-Host"] = []string{host}

	port := ""
	if _, p, err := net.SplitHostPort(host); err == nil {
		port = strings.TrimSpace(p)
	}
	if port == "" {
		port = defaultPort
	}
	h["X-Forwarded-Port"] = []string{port}
}

func deleteHeaderCI(h map[string][]string, key string) {
	if h == nil || key == "" {
		return
	}
	for k := range h {
		if strings.EqualFold(k, key) {
			delete(h, k)
		}
	}
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = r.Body.Close() }()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}
	return nil
}
