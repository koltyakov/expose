# Release signing

Expose uses the same key-custody approach as BBX: a JSON map of public Ed25519
keys pinned into each build, and a separate PKCS#8 PEM private key used only
for publishing. There is no certificate and no external verifier in the binary.

## GitHub configuration

Configure these settings in `koltyakov/expose` before publishing:

| Name | GitHub type | Value |
| --- | --- | --- |
| `RELEASE_SIGNING_PUBLIC_KEYS` | Repository variable | `{"release-2026-11-17":"<base64 raw 32-byte public key>"}` |
| `RELEASE_SIGNING_KEY_ID` | Repository variable | `release-2026-11-17` |
| `RELEASE_SIGNING_PRIVATE_KEY` | Secret in the `release` environment | Ed25519 private key in PKCS#8 PEM format |

These are Expose's own keys. Do not reuse BBX, TLS, or peer identity keys.
No feed initialization variable is needed. Releases use immutable per-tag metadata.
These names and scopes are shared with Control and BBX. Control also checks its
public variable against reviewed source pins. Public settings belong at repository
level; private keys belong only in the `release` environment, not repository secrets.

Store the local files under `~/.ssh/github/`: `expose.pem` is PKCS#8 private PEM,
`expose.pub` is SPKI public PEM, and `expose.json` is the public JSON key map.
Control uses the basename `control`; Browser Bridge uses `bbx`. The directory
must have mode `0700` and private keys `0600`.

Generate new keys on a trusted machine, outside the checkout. OpenSSL 3 can create
PKCS#8 PEM with `openssl genpkey -algorithm ED25519 -out "$HOME/.ssh/github/expose.pem"`.
Create the private directory first and never overwrite an existing key.
The public value is the base64 encoding of the raw 32-byte key, not PEM or a
base64-encoded SPKI structure. Keep an encrypted offline backup. Never commit,
print in CI, or attach the private key to a release.

Configure the `release` environment to accept only tags matching `v*.*.*`.
Protect release tags, restrict Actions secrets and publication access, and add
required approval for signing where available.
A compromised authorized release job can still steal an exportable key.
Public-key configuration changes are trust changes and require review.

Configure GitHub from the local files:

```sh
gh secret set RELEASE_SIGNING_PRIVATE_KEY --repo koltyakov/expose --env release \
  < "$HOME/.ssh/github/expose.pem"
gh variable set RELEASE_SIGNING_PUBLIC_KEYS --repo koltyakov/expose \
  --body "$(cat "$HOME/.ssh/github/expose.json")"
gh variable set RELEASE_SIGNING_KEY_ID --repo koltyakov/expose --body release-2026-11-17
```

Remove superseded signing secrets and variables after verifying the replacement.
The release workflow checks that the private key matches the active public pin
before invoking GoReleaser. Public keys are embedded in all six binaries and
in the generated `install.sh` and `install.ps1` release assets. Signing checks
the match again and verifies the result before writing the signature.
The workflow no longer needs cosign or `id-token: write`.

## Local tooling

Public-key configuration is build-time only. Setting `RELEASE_SIGNING_PUBLIC_KEYS`
on an installed executable cannot change its trust.

```sh
export RELEASE_SIGNING_PUBLIC_KEYS="$(cat "$HOME/.ssh/github/expose.json")"
make build
```

Ordinary local builds without this variable are allowed, but cannot authenticate
public updates. Release preparation and signing reject empty or invalid keys.
The public map supports up to 16 IDs, each up to 80 ASCII letters, digits,
periods, underscores, or hyphens.

The build-only helper is not shipped as an `expose` subcommand:

```sh
# Set the private key only in the signer's environment; never echo it.
export RELEASE_SIGNING_PUBLIC_KEYS="$(cat "$HOME/.ssh/github/expose.json")"
export RELEASE_SIGNING_KEY_ID=release-2026-11-17
export RELEASE_SIGNING_PRIVATE_KEY="$(cat "$HOME/.ssh/github/expose.pem")"
go run ./cmd/release-sign -mode check
go run ./cmd/release-sign -mode sign -tag v1.2.3 -manifest dist/checksums.txt
unset RELEASE_SIGNING_PRIVATE_KEY

# Verification needs only a public keyring obtained through a trusted channel.
go run ./cmd/release-sign -mode verify -tag v1.2.3 -manifest dist/checksums.txt

# Create ready-to-run installers with the same public pins.
go run ./cmd/release-sign -mode prepare -out tmp/release-installers
```

The signature path defaults to the manifest path plus `.sig`.
Manual verification must use a reviewed keyring, not a key supplied alongside
an untrusted download. Run the helper from trusted source.

Source files in `scripts/install.sh` and `scripts/install.ps1` are templates.
Use the prepared installers attached to a release. Unix needs `jq` and OpenSSL
3 or newer; Windows needs OpenSSL 3 or newer in PATH. System LibreSSL on macOS
does not implement this verification flow. Install a current OpenSSL first.
Missing dependencies or failed authentication stop installation.

## Signature format

`checksums.txt.sig` is a JSON envelope with exactly these fields:

```json
{
  "version": 1,
  "repository": "koltyakov/expose",
  "tag": "v1.2.3",
  "keyId": "release-2026-11-17",
  "signature": "<base64 Ed25519 signature>"
}
```

The signed message is the concatenation of this UTF-8 header and the exact
`checksums.txt` file bytes:

```text
expose-release-v1\n
koltyakov/expose\n
v1.2.3\n
release-2026-11-17\n
```

Here `\n` denotes a single LF byte, not literal backslash text. Header fields
cannot contain newlines. Checksum whitespace and the final newline are signed.
There is no JSON canonicalization. The envelope is limited to 4 KiB and the
checksum manifest to 1 MiB. Repository, tag, purpose/version, key ID, and signature
must all match. Keys are never fetched from the signature or a remote key service.

Installers first read the latest signature envelope, then download the checksum
manifest and archive from its exact tag. They authenticate the manifest before
requesting the archive. An unauthenticated tag cannot override a public pin.
The updater instead checks against the exact tag selected from the release API.

## Rotation and recovery

For planned rotation:

1. Add key B under a new ID while retaining A. Publish a bridge release signed
   by A, with binaries that trust both.
2. Upgrade installations to that bridge.
3. Keep both IDs unchanged. Switch the repository `RELEASE_SIGNING_KEY_ID`
   variable to B's ID, update the environment private-key secret to B, and publish.
4. Remove A from `RELEASE_SIGNING_PUBLIC_KEYS` after the transition.
   Do not leave a compromised key trusted.

Key IDs are signed and must remain stable throughout rotation. For
example, retain `release-2026-11-17` for A and add a new dated ID for B.
The build-time tool defaults to `RELEASE_SIGNING_KEY_ID`; `-key-id` can explicitly
select a different pinned ID. There is no hard-coded active ID or runtime override.
Clients that missed the bridge require a trusted reinstall. Do not assume an
old binary can learn a new public key from a release it cannot authenticate.

If the private key is lost, restore its encrypted offline backup. If no trusted
key is available, distribute a fresh pinned build through a trusted channel.

If the key is compromised, stop publication, revoke its CI access, investigate,
and create a new key on a trusted machine. Recover through a trusted reinstall.
A notice signed by the stolen key cannot reliably revoke that key in an old
binary. Do not assume GitHub or the build host remains trustworthy after a compromise.

## Clean cutover

There is no Sigstore compatibility path. Releases publish `checksums.txt.sig`,
not `checksums.txt.sigstore.json`. `EXPOSE_REQUIRE_SIGNATURE` is removed and cannot
enable a downgrade. Old strict updaters require a one-time trusted reinstall.
Upgrade checksum-only installations using the new prepared installer to establish
the pinned-key trust policy. Historical unsigned releases are rejected by new builds.
