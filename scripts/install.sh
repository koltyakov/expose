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

need_cmd tar
need_cmd mktemp
need_cmd install

os="$(asset_os)"
arch="$(asset_arch)"
asset="${binary}_${os}_${arch}.tar.gz"
url="https://github.com/${repo}/releases/latest/download/${asset}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

archive="$tmp_dir/$asset"
echo "Downloading $asset from $repo..."
download "$url" "$archive"

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
