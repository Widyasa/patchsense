#!/bin/sh
# Download the GitHub Release binary for this package version, check sha256,
# cache it, and exec it. Used by the Docker image. Does not compile Rust.
#
# version is the package version. It is not read from the environment.
# PATCHSENSE_BINARY skips the download and runs the given binary.
# PATCHSENSE_RELEASE_BASE overrides the download prefix (tests).
# PATCHSENSE_CACHE_DIR overrides the cache directory.
# PATCHSENSE_TARGET overrides target detection.
set -eu

version=0.1.0

fail() {
  echo "patchsense: $*" >&2
  exit 2
}

if [ -n "${PATCHSENSE_BINARY:-}" ]; then
  if [ ! -f "$PATCHSENSE_BINARY" ]; then
    fail "PATCHSENSE_BINARY=$PATCHSENSE_BINARY does not exist"
  fi
  exec "$PATCHSENSE_BINARY" "$@"
fi

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

base=${PATCHSENSE_RELEASE_BASE:-https://github.com/Widyasa/patchsense/releases/download}
base=${base%/}

if [ -n "${PATCHSENSE_TARGET:-}" ]; then
  triple=$PATCHSENSE_TARGET
else
  machine=$(uname -m)
  case "$machine" in
    x86_64|amd64) cpu=x86_64 ;;
    aarch64|arm64) cpu=aarch64 ;;
    *) fail "unsupported architecture $machine" ;;
  esac
  os=$(uname -s)
  case "$os" in
    Linux)
      libc=gnu
      if [ -f /etc/alpine-release ]; then
        libc=musl
      else
        ldd_out=$(ldd --version 2>&1 || true)
        case "$ldd_out" in
          *[Mm]usl*) libc=musl ;;
        esac
      fi
      triple="${cpu}-unknown-linux-${libc}"
      ;;
    Darwin) triple="${cpu}-apple-darwin" ;;
    MINGW*|MSYS*|CYGWIN*) triple="${cpu}-pc-windows-msvc" ;;
    *) fail "unsupported operating system $os" ;;
  esac
fi

case "$triple" in
  *windows*) bin=patchsense.exe ;;
  *) bin=patchsense ;;
esac

if [ -n "${PATCHSENSE_CACHE_DIR:-}" ]; then
  cache_root=$PATCHSENSE_CACHE_DIR
else
  if [ -z "${HOME:-}" ]; then
    fail "HOME is not set; set PATCHSENSE_CACHE_DIR"
  fi
  cache_root=$HOME/.cache/patchsense
fi
cache="$cache_root/bin/$version/$triple/$bin"
if [ -x "$cache" ]; then
  exec "$cache" "$@"
fi

prefix="$base/v$version"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

missing_release() {
  url=$1
  printf '%s\n' \
    "release v${version} is not published yet (${url} returned HTTP 404)." \
    "Install another way until that GitHub Release exists:" \
    "  cargo install patchsense --locked" \
    "  building from source: cargo build --release -p patchsense" \
    "Or set PATCHSENSE_BINARY=/path/to/patchsense"
}

fetch_to() {
  url=$1
  dest=$2
  code=$(curl --proto '=http,https' --tlsv1.2 -sS -L --retry 3 --max-redirs 5 \
    -o "$dest" -w '%{http_code}' "$url" || true)
  case "$code" in
    200) ;;
    404) fail "$(missing_release "$url")" ;;
    *) fail "download failed for $url: HTTP $code" ;;
  esac
}

fetch_to "$prefix/dist-manifest.json" "$tmp/manifest.json"

meta=$(jq -r --arg t "$triple" '
  [
    ((.artifacts // {}) | if type == "object" then to_entries[].value else .[] end),
    (.releases[]?.artifacts | if type == "object" then to_entries[].value else (. // [])[] end)
  ]
  | map(select(type == "object" and .kind == "executable-zip" and ((.target_triples // []) | index($t) != null)))
  | .[0]
  | if . == null or (.checksums.sha256 // "") == "" then empty
    else "\(.name) \(.checksums.sha256 | ascii_downcase)"
    end
' "$tmp/manifest.json") || fail "could not read the release manifest"
if [ -z "$meta" ]; then
  fail "no executable-zip for $triple in the v$version release"
fi
name=${meta%% *}
sha=${meta#* }
case "$name" in
  */*|*..*) fail "refusing archive name $name" ;;
esac

fetch_to "$prefix/$name" "$tmp/archive.tar.gz"
actual=$(sha256sum "$tmp/archive.tar.gz" | awk '{print $1}')
if [ "$actual" != "$sha" ]; then
  fail "checksum mismatch for $name"
fi

mkdir -p "$tmp/extract"
tar -xzf "$tmp/archive.tar.gz" --strip-components=1 -C "$tmp/extract"
if [ ! -f "$tmp/extract/$bin" ]; then
  fail "archive $name does not contain $bin"
fi
mkdir -p "$(dirname "$cache")"
cp "$tmp/extract/$bin" "$cache.partial"
chmod 0755 "$cache.partial"
mv "$cache.partial" "$cache"
rm -rf "$tmp"
trap - EXIT
exec "$cache" "$@"
