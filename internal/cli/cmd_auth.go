package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/access"
)

func runAuth(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "curl" {
		subArgs := args
		if len(subArgs) > 0 {
			subArgs = subArgs[1:]
		}
		return runAuthCurl(ctx, subArgs)
	}

	fmt.Fprintln(os.Stderr, "auth command error: expected `curl` subcommand")
	return 2
}

func runAuthCurl(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("auth-curl", flag.ContinueOnError)
	targetURL := ""
	user := envOr("EXPOSE_USER", "admin")
	password := envOr("EXPOSE_PASSWORD", "")
	insecure := false
	format := "curl"

	fs.StringVar(&targetURL, "url", targetURL, "Protected public URL to authenticate against")
	fs.StringVar(&user, "user", user, "Access-form username")
	fs.StringVar(&password, "password", password, "Access-form password")
	fs.BoolVar(&insecure, "insecure", insecure, "Skip TLS verification (useful for local sslip.io testing)")
	fs.StringVar(&format, "format", format, "Output format: curl|header|cookie")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "auth curl error:", err)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "auth curl error: unexpected positional arguments")
		return 2
	}

	reader := bufio.NewReader(os.Stdin)
	canPrompt := isInteractiveInput()
	var missing bool
	var err error

	targetURL, missing, err = resolveRequiredValueContext(ctx, reader, targetURL, canPrompt, "Protected URL: ")
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "auth curl canceled")
			return 130
		}
		fmt.Fprintln(os.Stderr, "auth curl error:", err)
		return 1
	}
	if missing {
		fmt.Fprintln(os.Stderr, "auth curl error: missing --url")
		return 2
	}
	targetURL, err = normalizeProtectedURL(targetURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "auth curl error:", err)
		return 2
	}

	user = strings.TrimSpace(user)
	if user == "" {
		user = "admin"
	}
	password = strings.TrimSpace(password)
	if password == "" {
		if !canPrompt {
			fmt.Fprintln(os.Stderr, "auth curl error: missing password: provide --password or EXPOSE_PASSWORD")
			return 2
		}
		password, err = promptSecretContext(ctx, "Protected route password: ")
		if err != nil {
			if errors.Is(err, context.Canceled) {
				fmt.Fprintln(os.Stderr, "auth curl canceled")
				return 130
			}
			fmt.Fprintln(os.Stderr, "auth curl error:", err)
			return 1
		}
		password = strings.TrimSpace(password)
		if password == "" {
			fmt.Fprintln(os.Stderr, "auth curl error: password is required")
			return 2
		}
	}

	authHeader, err := fetchProtectedRouteAuthHeader(ctx, targetURL, user, password, insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, "auth curl error:", err)
		return 1
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "curl":
		var b strings.Builder
		b.WriteString("curl ")
		if insecure {
			b.WriteString("-k ")
		}
		b.WriteString("-H ")
		b.WriteString(shellQuote(authHeader))
		b.WriteString(" ")
		b.WriteString(shellQuote(targetURL))
		fmt.Println(b.String())
	case "header":
		fmt.Println(authHeader)
	case "cookie":
		if strings.HasPrefix(authHeader, "Cookie: ") {
			fmt.Println(strings.TrimPrefix(authHeader, "Cookie: "))
			return 0
		}
		fmt.Fprintln(os.Stderr, "auth curl error: cookie output is only available for form-based protection")
		return 2
	default:
		fmt.Fprintln(os.Stderr, "auth curl error: format must be one of curl, header, cookie")
		return 2
	}

	return 0
}

func normalizeProtectedURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("missing protected URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid protected URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("protected URL must use http or https")
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", errors.New("protected URL must include host")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func fetchProtectedRouteAuthHeader(ctx context.Context, targetURL, user, password string, insecure bool) (string, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized && strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "basic") {
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		return "Authorization: Basic " + token, nil
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	next := parsed.RequestURI()
	if next == "" {
		next = "/"
	}

	form := url.Values{
		access.FormActionField:   {"login"},
		access.FormUserField:     {user},
		access.FormPasswordField: {password},
		access.FormNextField:     {next},
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msgText := strings.TrimSpace(string(msg))
		if msgText == "" {
			msgText = resp.Status
		}
		return "", fmt.Errorf("login failed: %s", msgText)
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == access.CookieName && strings.TrimSpace(cookie.Value) != "" {
			return "Cookie: " + cookie.Name + "=" + cookie.Value, nil
		}
	}
	return "", errors.New("login succeeded but access cookie was not returned")
}

func shellQuote(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}
