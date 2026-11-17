# Release signing

Expose uses the same key-custody approach as BBX: a JSON map of public Ed25519
keys pinned into each build, and a separate PKCS#8 PEM private key used only
for publishing. There is no certificate and no external verifier in the binary.

## GitHub configuration

Configure these settings in `koltyakov/expose` before publishing:

| Name | GitHub type | Value |
| --- | --- | --- |
| `EXPOSE_RELEASE_KEYS` | Actions variable | `{"release":"<base64 raw 32-byte public key>"}` |
| `EXPOSE_RELEASE_PRIVATE_KEY` | Actions secret | Ed25519 private key in PKCS#8 PEM format |

These are Expose's own keys. Do not reuse BBX, TLS, or peer identity keys.
No feed initialization variable is needed. Releases use immutable per-tag metadata.
Nothing in this migration provisions a production key or changes GitHub settings.

Generate the key on a trusted machine. For example, OpenSSL 3 can create
PKCS#8 PEM with `openssl genpkey -algorithm ED25519 -out release-private.pem`.
The public value is the base64 encoding of the raw 32-byte key, not PEM or a
base64-encoded SPKI structure. Keep an encrypted offline backup. Never commit,
print in CI, or attach the private key to a release.

Protect release tags, restrict Actions secrets and publication access, and
prefer protected GitHub environments with required approval for signing.
A compromised authorized release job can still steal an exportable key.
Public-key configuration changes are trust changes and require review.

The release workflow checks that the private key matches the `release` pin
before invoking GoReleaser. Public keys are embedded in all six binaries and
in the generated `install.sh` and `install.ps1` release assets. Signing checks
the match again and verifies the result before writing the signature.
The workflow no longer needs cosign or `id-token: write`.

## Local tooling

Public-key configuration is build-time only. Setting `EXPOSE_RELEASE_KEYS`
on an installed executable cannot change its trust.

```sh
export EXPOSE_RELEASE_KEYS='{"release":"<base64 raw public key>"}'
make build
```

Ordinary local builds without this variable are allowed, but cannot authenticate
public updates. Release preparation and signing reject empty or invalid keys.
The public map supports up to 16 IDs, each up to 80 ASCII letters, digits,
periods, underscores, or hyphens.

The build-only helper is not shipped as an `expose` subcommand:

```sh
# Private key must already be in EXPOSE_RELEASE_PRIVATE_KEY.
go run ./cmd/release-sign -mode check
go run ./cmd/release-sign -mode sign -tag v1.2.3 -manifest dist/checksums.txt

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
  "keyId": "release",
  "signature": "<base64 Ed25519 signature>"
}
```

The signed message is the concatenation of this UTF-8 header and the exact
`checksums.txt` file bytes:

```text
expose-release-v1\n
koltyakov/expose\n
v1.2.3\n
release\n
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
3. Keep both IDs unchanged. Switch the signer's `-key-id` and the workflow's
   configuration check to B's ID, update the private-key secret to B, and publish.
4. Remove A after the transition. Do not leave a compromised key trusted.

Key IDs are signed and must remain stable throughout rotation. For
example, retain `release` for A, add `next` for B, then sign with `-key-id next`
in GoReleaser after the bridge. Update the workflow's configuration check to the
same active ID. The default active ID is `release`; there is no runtime override.
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
