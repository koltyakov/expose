# Wildcard certificates with GoDaddy

Use Let's Encrypt and acme.sh to obtain a free wildcard certificate while
keeping DNS at GoDaddy. A separate ACME client handles DNS validation and
renewal; expose only loads the resulting certificate files. No expose
application code changes are required.

## Prerequisites

- A domain whose authoritative DNS is hosted by GoDaddy.
- Base-domain and wildcard DNS records pointing to the expose server. See
  [GoDaddy DNS setup](dns-godaddy.md).
- GoDaddy production DNS API access.
- A Linux server with systemd, Bash, OpenSSL, curl, and a working cron service.
- [acme.sh](https://github.com/acmesh-official/acme.sh) installed for root at
  `/root/.acme.sh`, with its renewal cron job enabled. Prefer a verified signed
  release and follow the upstream installation instructions.

The examples use `example.com` as a placeholder. Replace it with your
`EXPOSE_DOMAIN` everywhere, including in the restart hook. For a base domain
such as `tunnels.example.com`, request both that name and
`*.tunnels.example.com`.

Commands assume a root Bash shell and an `expose.service` systemd unit running
as `expose:expose`. Adjust the service name, account, group, and paths for your
installation.

## How it works

1. acme.sh adds temporary TXT values at `_acme-challenge.example.com` through
   GoDaddy's API.
2. Let's Encrypt checks those values using DNS-01 and issues one certificate
   covering `example.com` and `*.example.com`.
3. acme.sh removes the temporary values and installs the certificate files.
4. expose serves the certificate in `wildcard` mode instead of issuing
   certificates for individual tunnel hostnames.
5. Scheduled renewal checks obtain a new certificate when due, install it, and
   run a validation and restart hook.

DNS-01 does not require inbound port 80. Normal HTTPS still needs public TCP
443; HTTP/3 also needs UDP 443. Keep the existing DNS routing records in place.

A certificate for `*.example.com` covers `app.example.com`, but not
`nested.app.example.com` or the base domain itself. Request the base domain
separately in the same certificate. Wildcard TLS reduces per-host disclosure in
Certificate Transparency logs; it does not replace authentication.

## Create GoDaddy credentials

Let's Encrypt issuance is free. GoDaddy provides DNS API access for accounts
with an active domain; check its
[current API access requirements](https://www.godaddy.com/help/how-do-i-access-domain-related-apis-42424).
Buying a GoDaddy SSL certificate is not required.

Create a **classic production API key and secret** through the
[classic Developer Portal](https://classic-developer.godaddy.com/keys), completing
identity verification if requested. OTE keys target the test environment. The
acme.sh `dns_gd` integration described here expects `GD_Key` and `GD_Secret`,
not a personal access token.

Enter the values directly on the server using hidden prompts. This Bash
subshell writes a root-only credential file without putting the values in
command history:

```bash
(
  set -e
  umask 077
  install -d -o root -g root -m 0700 /root/.config/expose-acme
  read -r -s -p 'GoDaddy production API key: ' GD_Key
  printf '\n'
  read -r -s -p 'GoDaddy production API secret: ' GD_Secret
  printf '\n'
  test -n "$GD_Key" && test -n "$GD_Secret"
  printf 'export GD_Key=%q\nexport GD_Secret=%q\n' "$GD_Key" "$GD_Secret" \
    > /root/.config/expose-acme/godaddy.env
  chown root:root /root/.config/expose-acme/godaddy.env
  chmod 0600 /root/.config/expose-acme/godaddy.env
)
```

acme.sh also saves the credentials in its `account.conf` for unattended
renewal. Keep `/root/.acme.sh` mode `700` and its credential files mode `600`,
owned by root. The expose service account should not have access to them.

Do not put credential values in chat, Git, screenshots, or documentation.
Never display the credential files or share debug logs without checking for
secrets.

## Issue the certificate

Explicitly select Let's Encrypt rather than relying on the client's default CA:

```bash
(
  set -e
  umask 077
  . /root/.config/expose-acme/godaddy.env
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  /root/.acme.sh/acme.sh --issue \
    --server letsencrypt \
    --dns dns_gd \
    -d example.com \
    -d '*.example.com' \
    --keylength ec-256
)
```

Wait for DNS validation, issuance, and TXT cleanup to complete. Do not point
expose directly at acme.sh's internal working files. Use `--install-cert` to
copy the full chain and key into stable paths and register their renewal
destinations.

## Prepare certificate permissions

Use a root-owned directory that the expose group can read but not modify:

```bash
install -d -o root -g expose -m 0750 /etc/expose-tls
touch /etc/expose-tls/wildcard.crt /etc/expose-tls/wildcard.key
chown root:expose /etc/expose-tls/wildcard.crt /etc/expose-tls/wildcard.key
chmod 0644 /etc/expose-tls/wildcard.crt
chmod 0640 /etc/expose-tls/wildcard.key
```

`touch` preserves existing file contents when reconfiguring a service.
acme.sh preserves existing target-file permissions during installation.
Keep these files separate from root-only API credentials and from directories
writable by the expose service account.

## Install a restart hook

expose loads static certificates at startup. Replacing files alone does not
update the certificate served by the running process.

Save the following script as `/usr/local/sbin/expose-reload-wildcard`, replacing
the example domain and service name as needed:

```bash
#!/bin/bash
set -euo pipefail

domain=example.com
service=expose.service
cert=/etc/expose-tls/wildcard.crt
key=/etc/expose-tls/wildcard.key
dropin=/etc/systemd/system/expose.service.d/wildcard-tls.conf

openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null
openssl x509 -in "$cert" -noout -checkhost "$domain" | grep -q 'does match certificate'
openssl x509 -in "$cert" -noout -checkhost "wildcard-check.$domain" | grep -q 'does match certificate'
openssl verify -purpose sslserver -untrusted "$cert" "$cert" >/dev/null
openssl pkey -in "$key" -check -noout >/dev/null
cert_public_key=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256)
private_public_key=$(openssl pkey -in "$key" -pubout -outform DER | openssl dgst -sha256)
if [[ "$cert_public_key" != "$private_public_key" ]]; then
    echo "Certificate and private key do not match; expose was not restarted." >&2
    exit 1
fi

# Validate the first installation before enabling wildcard mode.
if [[ ! -f "$dropin" ]]; then
    echo "Certificate validated. Wildcard mode is not enabled yet; no restart needed."
    exit 0
fi

systemctl restart "$service"
systemctl is-active --quiet "$service"
curl --fail --silent --show-error --output /dev/null \
    --connect-timeout 5 --max-time 10 \
    --retry 8 --retry-delay 1 --retry-connrefused \
    "https://$domain/_expose/healthz"
logger -t expose-acme "Wildcard certificate deployed; expose restarted and HTTPS health check passed."
echo "Expose restarted; HTTPS health check passed."
```

Set ownership and executable permissions:

```bash
chown root:root /usr/local/sbin/expose-reload-wildcard
chmod 0755 /usr/local/sbin/expose-reload-wildcard
bash -n /usr/local/sbin/expose-reload-wildcard
```

The hook checks remaining validity, hostname coverage, chain trust, and the
certificate/key match before restarting. It then checks HTTPS through public
DNS without disabling certificate verification. Restarts briefly interrupt
connections; expose clients reconnect.

## Install the certificate files

Run this after the hook is in place:

```bash
/root/.acme.sh/acme.sh --install-cert -d example.com --ecc \
  --key-file /etc/expose-tls/wildcard.key \
  --fullchain-file /etc/expose-tls/wildcard.crt \
  --reloadcmd /usr/local/sbin/expose-reload-wildcard
```

This copies the current certificate and saves the paths and hook for renewals.
On the first installation, the hook validates the files without restarting
because the wildcard systemd drop-in does not exist yet.

## Enable wildcard mode

Back up the current service configuration in a root-only directory. If the
wildcard drop-in already exists, back it up before editing it. Leave unrelated
unit settings and existing per-host certificate caches intact.

Create `/etc/systemd/system/expose.service.d/wildcard-tls.conf`:

```ini
[Service]
Environment="EXPOSE_TLS_MODE=wildcard"
Environment="EXPOSE_TLS_CERT_FILE=/etc/expose-tls/wildcard.crt"
Environment="EXPOSE_TLS_KEY_FILE=/etc/expose-tls/wildcard.key"
```

Check for conflicting TLS command-line flags or `EnvironmentFile` settings,
then confirm the service account can read the key and apply the configuration:

```bash
runuser -u expose -- test -r /etc/expose-tls/wildcard.key
systemctl daemon-reload
/usr/local/sbin/expose-reload-wildcard
```

If activation fails, restore the previous TLS settings using the rollback
procedure below. Do not assume a successful file copy means the running
server has loaded the new certificate.

## Automatic renewal

Verify that the acme.sh installer registered a renewal entry in root's crontab
and that the cron service is running. Do not add duplicate renewal jobs:

```bash
crontab -l
```

Scheduled checks do not issue a certificate every time. acme.sh renews when
due, using the CA's ACME Renewal Information schedule when available. The saved
GoDaddy credentials handle DNS-01; the saved install settings copy the new
files and run the restart hook.

Run the normal due-date check manually with:

```bash
/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
```

Avoid `--force` during routine checks; it requests another certificate and can
consume CA rate limits. If credentials are rotated, update `godaddy.env` using
the hidden prompts and source it in the same shell as the next DNS-01 issuance
or renewal. Updating that file alone does not change acme.sh's saved
credentials, and a skipped renewal does not refresh them. Confirm a successful
renewal with the replacement credentials before revoking a still-needed key.

## Verify and maintain the setup

Check service status, expiry, key readability, and HTTPS health:

```bash
systemctl is-active expose
openssl x509 -in /etc/expose-tls/wildcard.crt -noout -dates -ext subjectAltName
openssl x509 -in /etc/expose-tls/wildcard.crt -noout -checkend 604800
runuser -u expose -- test -r /etc/expose-tls/wildcard.key
curl --fail --silent --show-error https://example.com/_expose/healthz
curl --fail --silent --show-error https://wildcard-check.example.com/_expose/healthz
journalctl -t expose-acme
```

`-checkend 604800` fails if the installed certificate expires within seven days.
Both HTTPS checks should return `ok`. Test a previously unused subdomain to
confirm wildcard coverage rather than relying on an older per-host certificate.

Inspect the certificate actually served, rather than just the disk file:

```bash
set -o pipefail
openssl s_client -connect example.com:443 -servername example.com \
  -verify_hostname example.com -verify_return_error </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -ext subjectAltName -fingerprint -sha256
```

Repeat with a subdomain and compare certificate fingerprints. The base domain
and subdomain should serve the same wildcard certificate.

The hook logs successful deployments, not every scheduled check. The default
cron output settings do not provide an alerting service. Monitor public
certificate expiry separately; a cron entry alone does not prove future
renewals will succeed.

If validation fails, the hook stops before restarting. If expose still serves
the old certificate after renewal, inspect the hook and service status.
Running `/usr/local/sbin/expose-reload-wildcard` validates and restarts the
service; account for its brief interruption.

## Roll back the TLS configuration

If the wildcard drop-in was newly added, move it to a root-only backup directory
to restore the underlying unit settings:

```bash
install -d -o root -g root -m 0700 /root/.config/expose-acme/backups
backup=$(mktemp -d /root/.config/expose-acme/backups/rollback-XXXXXXXX)
mv /etc/systemd/system/expose.service.d/wildcard-tls.conf "$backup/"
systemctl daemon-reload
systemctl restart expose
curl --fail --silent --show-error https://example.com/_expose/healthz
```

If a wildcard drop-in existed before this setup, restore its previous contents
instead of removing it. Confirm the underlying configuration selects the
intended TLS mode.

`auto` and `dynamic` need reachable ACME challenge ports when obtaining new
per-host certificates, and those certificate names appear in CT logs. Keep any
existing per-host cache for fallback. Removing the drop-in does not delete the
wildcard files or stop acme.sh renewal; the example hook validates the files but
does not restart expose while the drop-in is absent.

## References

- [TLS modes](tls-modes.md)
- [GoDaddy DNS setup](dns-godaddy.md)
- [VPS deployment](vps-deployment.md)
- [Let's Encrypt challenge types](https://letsencrypt.org/docs/challenge-types/)
- [acme.sh usage and certificate installation](https://github.com/acmesh-official/acme.sh)
- [GoDaddy DNS plugin](https://github.com/acmesh-official/acme.sh/blob/master/dnsapi/dns_gd.sh)
