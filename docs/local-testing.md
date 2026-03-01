# Local Testing

Validate end-to-end behavior on a single machine using `127.0.0.1.sslip.io`.

This guide covers:
- local HTTPS server in wildcard mode
- tunnel client connection to local server on `:10443`
- password-protected tunnel verification

## Prerequisites

- macOS/Linux shell
- Go 1.23+
- `mkcert` installed

## 1) Start local app

```bash
python3 -m http.server 3000
```

## 2) Generate local wildcard certs

```bash
brew install mkcert nss
mkcert -install
mkdir -p cert
mkcert -cert-file cert/wildcard.crt -key-file cert/wildcard.key "*.127.0.0.1.sslip.io" "127.0.0.1.sslip.io"
```

## 3) Start expose server (wildcard mode)

```bash
export EXPOSE_DOMAIN=127.0.0.1.sslip.io
export EXPOSE_TLS_MODE=wildcard
export EXPOSE_TLS_CERT_FILE=./cert/wildcard.crt
export EXPOSE_TLS_KEY_FILE=./cert/wildcard.key
./bin/expose server
```

## 4) Create API key

```bash
./bin/expose apikey create --name local
```

Copy the `api_key` value from output.

## 5) Start protected client tunnel

```bash
export EXPOSE_DOMAIN=https://127.0.0.1.sslip.io:10443
export EXPOSE_API_KEY=<YOUR_API_KEY>
export EXPOSE_USER=admin
export EXPOSE_PASSWORD=123
./bin/expose http --domain=myapp --protect 3000
```

Notes:
- `EXPOSE_USER` is optional; default is `admin`.
- If `--protect` is set and `EXPOSE_PASSWORD` is missing, CLI prompts interactively.
- Client reads `.env` automatically when present.

## 6) Verify protected access behavior

```bash
curl -k -i https://myapp.127.0.0.1.sslip.io:10443/
./bin/expose auth curl --url https://myapp.127.0.0.1.sslip.io:10443/ --password 123 --insecure
curl -k -i -H "$(./bin/expose auth curl --url https://myapp.127.0.0.1.sslip.io:10443/ --password 123 --insecure --format header)" \
  https://myapp.127.0.0.1.sslip.io:10443/
```

Expected:
- first request: `401 Unauthorized` with the HTML access form
- `expose auth curl`: prints a ready-to-run `curl` command with the access cookie
- curl with helper-provided header: upstream `200` response
