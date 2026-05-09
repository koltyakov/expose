#!/bin/sh
set -eu

install_dir="$HOME/.local/bin"
binary="expose"

usage() {
  cat <<'EOF'
Uninstall expose.

Removes expose from $HOME/.local/bin.

Examples:
  curl -fsSL https://raw.githubusercontent.com/koltyakov/expose/main/scripts/uninstall.sh | sh
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

target="$install_dir/$binary"

if [ ! -e "$target" ]; then
  echo "$binary is not installed at $target"
  exit 0
fi

rm -f "$target"
echo "Removed $target"
