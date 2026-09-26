#!/bin/sh
# Install docker-trim.
#
#   curl -fsSL https://raw.githubusercontent.com/mkamranr/docker-trim/main/install.sh | sh
#
# Environment:
#   DOCKER_TRIM_VERSION   version to install, without the leading v (default: latest release)
#   DOCKER_TRIM_BIN_DIR   where to put the binary (default: /usr/local/bin, else ~/.local/bin)
set -eu

REPO="mkamranr/docker-trim"
NAME="docker-trim"

say() { printf '%s\n' "$*"; }
die() { printf '%s: %s\n' "$NAME" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

# curl and wget are both common enough that requiring one specifically is rude.
if need curl; then
  fetch() { curl -fsSL "$1"; }
  fetch_to() { curl -fsSL -o "$2" "$1"; }
elif need wget; then
  fetch() { wget -qO- "$1"; }
  fetch_to() { wget -qO "$2" "$1"; }
else
  die "needs curl or wget"
fi

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) die "unsupported operating system: $os. On Windows, download a release from https://github.com/$REPO/releases" ;;
esac
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac
target="${os}-${arch}"

version="${DOCKER_TRIM_VERSION:-}"
if [ -z "$version" ]; then
  say "Looking up the latest release..."
  version=$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' \
    | head -n 1)
  [ -n "$version" ] || die "could not determine the latest release; set DOCKER_TRIM_VERSION"
fi

archive="${NAME}-${version}-${target}.tar.gz"
url="https://github.com/$REPO/releases/download/v${version}/${archive}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $NAME $version for $target..."
fetch_to "$url" "$tmp/$archive" || die "download failed: $url"

# Checksums are verified when both the file and a tool to check it are available;
# a missing .sha256 is not a reason to refuse to install.
if fetch_to "${url}.sha256" "$tmp/$archive.sha256" 2>/dev/null; then
  if need sha256sum; then
    sum=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
  elif need shasum; then
    sum=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
  else
    sum=""
  fi
  if [ -n "$sum" ]; then
    want=$(cut -d' ' -f1 < "$tmp/$archive.sha256")
    [ "$sum" = "$want" ] || die "checksum mismatch: expected $want, got $sum"
    say "Checksum verified."
  fi
fi

tar -xzf "$tmp/$archive" -C "$tmp" || die "could not extract $archive"
binary=$(find "$tmp" -type f -name "$NAME" -perm -u+x | head -n 1)
[ -n "$binary" ] || die "no $NAME binary inside $archive"

bindir="${DOCKER_TRIM_BIN_DIR:-}"
if [ -z "$bindir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then
    bindir=/usr/local/bin
  else
    bindir="$HOME/.local/bin"
  fi
fi
mkdir -p "$bindir" || die "cannot create $bindir"
install -m 0755 "$binary" "$bindir/$NAME" 2>/dev/null \
  || { cp "$binary" "$bindir/$NAME" && chmod 0755 "$bindir/$NAME"; } \
  || die "cannot write to $bindir"

say "Installed $NAME $version to $bindir/$NAME"

case ":$PATH:" in
  *":$bindir:"*) ;;
  *) say ""; say "Note: $bindir is not on your PATH. Add it with:"; say "  export PATH=\"$bindir:\$PATH\"" ;;
esac

say ""
say "Try it:"
say "  $NAME --analyze-only -f Dockerfile"
