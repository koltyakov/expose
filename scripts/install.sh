#!/bin/sh
set -eu

repo="koltyakov/expose"
install_dir="$HOME/.local/bin"
binary="expose"

usage() {
  cat <<'EOF'
Install expose from GitHub Releases.

Installs the latest release to $HOME/.local/bin.

Examples:
  curl -fsSL https://raw.githubusercontent.com/koltyakov/expose/main/scripts/install.sh | sh
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
    curl -fsSL "$url" -o "$out"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
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

need_cmd tar
need_cmd mktemp
need_cmd install
need_cmd awk

os="$(asset_os)"
arch="$(asset_arch)"
asset="${binary}_${os}_${arch}.tar.gz"
base_url="https://github.com/${repo}/releases/latest/download"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

archive="$tmp_dir/$asset"
checksums="$tmp_dir/checksums.txt"
echo "Downloading $asset from $repo..."
download "$base_url/$asset" "$archive"
download "$base_url/checksums.txt" "$checksums"
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
