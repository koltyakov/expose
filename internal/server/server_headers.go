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
// chain so trusted proxy hops can extend an existing chain.
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

// getAndNormalizeForwardedFor joins all X-Forwarded-For header values and
// canonicalizes the header key in-place.
func getAndNormalizeForwardedFor(h map[string][]string) string {
	if h == nil {
		return ""
	}
	if vals, ok := h["X-Forwarded-For"]; ok {
		return joinForwardedForValues(vals)
	}
	var values []string
	for k, vals := range h {
		if !strings.EqualFold(k, "X-Forwarded-For") {
			continue
		}
		values = append(values, vals...)
		delete(h, k)
	}
	return joinForwardedForValues(values)
}

func joinForwardedForValues(values []string) string {
	nonEmpty := values[:0]
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			nonEmpty = append(nonEmpty, value)
		}
	}
	return strings.Join(nonEmpty, ", ")
}

// injectForwardedProxyHeaders overwrites proxy-derived host, protocol, and
// port headers to reflect the public request. X-Forwarded-For is preserved so
// injectForwardedFor can append the immediate peer to its existing chain.
func injectForwardedProxyHeaders(h map[string][]string, r *http.Request) {
	if h == nil || r == nil {
		return
	}

	host := strings.TrimSpace(r.Host)
	if host == "" {
		return
	}

	deleteProxyHeaders(h)

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

// proxyHeadersToReplace are the headers injectForwardedProxyHeaders rewrites,
// in canonical form.
var proxyHeadersToReplace = []string{
	"Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
}

// deleteProxyHeaders removes every case-insensitive spelling of the headers we
// are about to set. Keys arrive canonicalized by net/http, so the common case
// is a handful of direct map deletes; the full scan only runs if a
// non-canonical spelling is actually present, which a client can force but
// which costs one pass rather than one pass per header.
func deleteProxyHeaders(h map[string][]string) {
	if h == nil {
		return
	}

	for _, key := range proxyHeadersToReplace {
		delete(h, key)
	}

	// Any remaining key that folds onto one of the canonical names was
	// spelled non-canonically and still needs removing.
	var nonCanonical []string
	for k := range h {
		if isProxyHeaderName(k) {
			nonCanonical = append(nonCanonical, k)
		}
	}
	for _, k := range nonCanonical {
		delete(h, k)
	}
}

func isProxyHeaderName(key string) bool {
	for _, candidate := range proxyHeadersToReplace {
		if len(key) == len(candidate) && strings.EqualFold(key, candidate) {
			return true
		}
	}
	return false
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
