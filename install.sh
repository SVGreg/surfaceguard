#!/bin/sh
# Install surfaceguard from GitHub Releases (no Go toolchain required).
#
#   curl -fsSL https://raw.githubusercontent.com/SVGreg/surfaceguard/main/install.sh | sh
#
# Environment overrides:
#   VERSION       release tag to install (e.g. v0.3.0); default: latest
#   INSTALL_DIR   target directory; default: /usr/local/bin
#   GITHUB_TOKEN  optional; only used to authenticate the "latest release"
#                 lookup, which is anonymous-rate-limited per IP. Release
#                 assets themselves are public and fetched without it.
set -eu

REPO="SVGreg/surfaceguard"
BINARY="surfaceguard"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

err() { echo "install.sh: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || err "curl is required"
command -v tar >/dev/null 2>&1 || err "tar is required"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) err "unsupported OS: $os (on Windows, download the .zip from https://github.com/$REPO/releases)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) err "unsupported architecture: $arch" ;;
esac

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  api="https://api.github.com/repos/$REPO/releases/latest"
  # Spelled out twice rather than once with ${GITHUB_TOKEN:+-H "..."}: that
  # expansion is unquoted, so the shell would split the header into four
  # arguments and send a malformed request.
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    latest=$(curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$api" || true)
  else
    latest=$(curl -fsSL "$api" || true)
  fi
  VERSION=$(printf '%s' "$latest" | grep -m1 '"tag_name"' | cut -d '"' -f 4)
  [ -n "$VERSION" ] || err "could not determine the latest release tag (GitHub API rate limit? set VERSION=vX.Y.Z or GITHUB_TOKEN)"
fi

vnum="${VERSION#v}"
base="https://github.com/$REPO/releases/download/$VERSION"

asset="${BINARY}_${vnum}_${os}_${arch}.tar.gz"
inner="$BINARY"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $BINARY $VERSION ($os/$arch)..."
curl -fsSL -o "$tmp/$asset" "$base/$asset" 2>/dev/null || err "download failed: $base/$asset
(releases before v0.4.0 published a differently named asset and cannot be installed by this script)"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || err "download failed: $base/checksums.txt"

(
  cd "$tmp"
  expected=$(grep " $asset\$" checksums.txt | cut -d ' ' -f 1)
  [ -n "$expected" ] || err "no checksum for $asset in checksums.txt"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$asset" | cut -d ' ' -f 1)
  else
    actual=$(shasum -a 256 "$asset" | cut -d ' ' -f 1)
  fi
  [ "$expected" = "$actual" ] || err "checksum mismatch for $asset"
)

tar -xzf "$tmp/$asset" -C "$tmp" "$inner"

echo "Installing to $INSTALL_DIR/$BINARY..."
if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$tmp/$inner" "$INSTALL_DIR/$BINARY"
else
  echo "$INSTALL_DIR is not writable; retrying with sudo..."
  sudo install -m 0755 "$tmp/$inner" "$INSTALL_DIR/$BINARY"
fi

echo "Installed: $("$INSTALL_DIR/$BINARY" version | head -1)"
