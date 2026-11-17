#!/bin/sh
set -eu

repo="koltyakov/expose"
install_dir="$HOME/.local/bin"
binary="expose"
# Filled by release-sign -mode prepare. Never read trust keys from the environment.
pinned_keys='EXPOSE_PINNED_RELEASE_KEYS'

usage() {
  cat <<'EOF'
Install expose from GitHub Releases.

Installs the latest release to $HOME/.local/bin.

Examples:
  curl -fsSL https://github.com/koltyakov/expose/releases/latest/download/install.sh | sh
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command: $1" >&2
    exit 1
  fi
}

asset_os() {
  case "$(uname -s)" in
    Darwin) printf '%s' Darwin ;;
    Linux) printf '%s' Linux ;;
    *)
      echo "error: unsupported OS: $(uname -s)" >&2
      exit 1
      ;;
  esac
}

asset_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf '%s' x86_64 ;;
    arm64 | aarch64) printf '%s' arm64 ;;
    *)
      echo "error: unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

download() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --proto-redir '=https' -fsSL "$url" -o "$out"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget --https-only -qO "$out" "$url"
    return
  fi
  echo "error: missing required command: curl or wget" >&2
  exit 1
}

sha256_of() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  echo "error: missing required command: sha256sum or shasum" >&2
  exit 1
}

verify_checksum() {
  archive_path="$1"
  asset_name="$2"
  checksums_path="$3"
  expected="$(awk -v asset="$asset_name" '$2 == asset || $2 == "*"asset {print tolower($1)}' "$checksums_path" | head -n1)"
  if [ -z "$expected" ]; then
    echo "error: no checksum entry for $asset_name in checksums.txt" >&2
    exit 1
  fi
  actual="$(sha256_of "$archive_path")"
  if [ "$actual" != "$expected" ]; then
    echo "error: checksum mismatch for $asset_name" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
  fi
  echo "Checksum verified for $asset_name"
}

verify_signature() {
  checksums_path="$1"
  [ "$(wc -c < "$checksums_path")" -le 1048576 ] || { echo "error: manifest too large" >&2; exit 1; }
  public_key="$(printf '%s' "$pinned_keys" | jq -er --arg id "$key_id" '.[$id] | strings | select(test("^[A-Za-z0-9+/]{43}=$"))')"
  printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$public_key" '-----END PUBLIC KEY-----' > "$tmp_dir/key.pem"
  jq -jr '.signature' "$signature" | openssl base64 -d -A > "$tmp_dir/signature.bin"
  [ "$(wc -c < "$tmp_dir/signature.bin")" -eq 64 ] || { echo "error: invalid signature" >&2; exit 1; }
  {
    printf 'expose-release-v1\n%s\n%s\n%s\n' "$repo" "$tag" "$key_id"
    cat "$checksums_path"
  } > "$tmp_dir/signed"
  openssl pkeyutl -verify -pubin -inkey "$tmp_dir/key.pem" -rawin -in "$tmp_dir/signed" -sigfile "$tmp_dir/signature.bin"
  echo "Signature verified for checksums.txt"
}

need_cmd tar
need_cmd mktemp
need_cmd install
need_cmd awk
need_cmd jq
need_cmd openssl
# LibreSSL and older OpenSSL do not implement this Ed25519 verification flow.
case "$(openssl version)" in
  "OpenSSL 3."* | "OpenSSL 4."*) ;;
  *) echo "error: OpenSSL 3 or newer is required for Ed25519 verification" >&2; exit 1 ;;
esac
printf '%s' "$pinned_keys" | jq -e 'type == "object" and length > 0' >/dev/null || {
  echo "error: use the prepared installer attached to a release" >&2
  exit 1
}

os="$(asset_os)"
arch="$(asset_arch)"
asset="${binary}_${os}_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/latest/download"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

archive="$tmp_dir/$asset"
checksums="$tmp_dir/checksums.txt"
signature="$tmp_dir/checksums.txt.sig"
echo "Downloading $asset from $repo..."
# Resolve latest once through its signed envelope, then use only immutable tag URLs.
download "$base_url/checksums.txt.sig" "$signature"
[ "$(wc -c < "$signature")" -le 4096 ] || { echo "error: signature too large" >&2; exit 1; }
jq -e --arg repo "$repo" '
  type == "object" and
  (keys == ["keyId", "repository", "signature", "tag", "version"]) and
  .version == 1 and .repository == $repo and
  (.tag | strings | test("^v[0-9][a-zA-Z0-9.+_-]{0,127}$")) and
  (.keyId | strings | test("^[a-zA-Z0-9._-]{1,80}$")) and
  (.signature | strings | test("^[A-Za-z0-9+/]{86}==$"))
' "$signature" >/dev/null
tag="$(jq -er '.tag' "$signature")"
key_id="$(jq -er '.keyId' "$signature")"
base_url="https://github.com/${repo}/releases/download/$tag"
download "$base_url/checksums.txt" "$checksums"
verify_signature "$checksums"
download "$base_url/$asset" "$archive"
verify_checksum "$archive" "$asset" "$checksums"

tar -xzf "$archive" -C "$tmp_dir"
if [ ! -f "$tmp_dir/$binary" ]; then
  echo "error: $binary not found in $asset" >&2
  exit 1
fi

mkdir -p "$install_dir"
install -m 0755 "$tmp_dir/$binary" "$install_dir/$binary"

echo "Installed $binary to $install_dir/$binary"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *)
    echo "Note: $install_dir is not on PATH."
    echo "Add it to your shell profile, or run: $install_dir/$binary"
    ;;
esac
