package client

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// registerError is a structured error from the server's registration endpoint.
type registerError struct {
	StatusCode int
	Message    string
	Code       string
}

func (e *registerError) Error() string {
	return e.Message
}

func isNonRetriableRegisterError(err error) bool {
	if err == nil {
		return false
	}
	var re *registerError
	if errors.As(err, &re) {
		if re.Code == "hostname_in_use" {
			return true
		}
		// Retry for backpressure and transient timeout statuses.
		if re.StatusCode == http.StatusTooManyRequests || re.StatusCode == http.StatusRequestTimeout {
			return false
		}
		// Other 4xx statuses are usually auth or request-shape errors and should
		// fail fast instead of reconnect-looping forever.
		return re.StatusCode >= 400 && re.StatusCode < 500
	}
	// Fallback for plain-text errors from older servers.
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "hostname already in use") {
		return true
	}
	return strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "invalid mode") ||
		strings.Contains(msg, "invalid json") ||
		strings.Contains(msg, "requires subdomain")
}

// shortenError extracts the innermost meaningful message from nested network
// errors (e.g. *url.Error → *net.OpError → syscall) so that display messages
// stay concise (e.g. "connection refused" instead of the full dial trace).
func shortenError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

func isTLSProvisioningInProgressError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "failed to verify certificate") ||
		strings.Contains(msg, "certificate is not standards compliant") ||
		strings.Contains(msg, "x509:")
}

func isNonReleaseVersion(version string) bool {
	version = strings.TrimSpace(version)
	return version == "" || version == "dev" || strings.HasSuffix(version, "-dev")
}
