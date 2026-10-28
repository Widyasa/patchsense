#!/bin/sh
# Exercise release-binary launchers against a local fake GitHub release.
# No network beyond 127.0.0.1. No Rust compile.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

cargo_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
php_version=$(sed -n "s/^const PATCHSENSE_VERSION = '\\(.*\\)';/\\1/p" bin/patchsense)
composer_version=$(php -r 'echo json_decode(file_get_contents("composer.json"), true)["version"];')
shell_version=$(sed -n 's/^version=//p' scripts/fetch-release.sh)
go_version=$(sed -n 's/^const patchsenseVersion = "\(.*\)"$/\1/p' go/cmd/patchsense/main.go)
if [ "$cargo_version" != "0.1.0" ] \
  || [ "$php_version" != "$cargo_version" ] \
  || [ "$composer_version" != "$cargo_version" ] \
  || [ "$shell_version" != "$cargo_version" ] \
  || [ "$go_version" != "$cargo_version" ]; then
  echo "version pin mismatch cargo=$cargo_version php=$php_version composer=$composer_version shell=$shell_version go=$go_version" >&2
  exit 1
fi

stage=$(mktemp -d)
cache=$(mktemp -d)
log=$(mktemp)
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$stage" "$cache" "$log"
}
trap cleanup EXIT

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

write_manifest() {
  archive=$1
  sha=$(sha256sum "$archive" | awk '{print $1}')
  name=$(basename "$archive")
  cat > "$stage/releases/download/v0.1.0/dist-manifest.json" <<EOF
{
  "artifacts": {
    "$name": {
      "name": "$name",
      "kind": "executable-zip",
      "target_triples": ["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"],
      "checksums": { "sha256": "$sha" }
    }
  }
}
EOF
}

pack_binary() {
  src=$1
  work=$(mktemp -d)
  mkdir -p "$work/patchsense-x86_64-unknown-linux-gnu"
  cp "$src" "$work/patchsense-x86_64-unknown-linux-gnu/patchsense"
  chmod 0755 "$work/patchsense-x86_64-unknown-linux-gnu/patchsense"
  mkdir -p "$stage/releases/download/v0.1.0"
  archive="$stage/releases/download/v0.1.0/patchsense-x86_64-unknown-linux-gnu.tar.gz"
  tar -C "$work" -czf "$archive" patchsense-x86_64-unknown-linux-gnu
  rm -rf "$work"
  write_manifest "$archive"
}

start_server() {
  python3 -m http.server "$port" --bind 127.0.0.1 --directory "$stage" >"$log" 2>&1 &
  server_pid=$!
  i=0
  while [ "$i" -lt 50 ]; do
    if curl -fsS "http://127.0.0.1:$port/releases/download/v0.1.0/dist-manifest.json" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 0.05
  done
  echo "fake release server did not start" >&2
  cat "$log" >&2
  exit 1
}

stop_server() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=""
  fi
}

fake=$(mktemp)
cat > "$fake" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--exit" ]; then
  exit "$2"
fi
if [ "${1:-}" = "--version" ]; then
  echo "fake-patchsense 0.1.0"
  exit 0
fi
printf 'args:%s\n' "$*"
exit 0
EOF
chmod 0755 "$fake"
pack_binary "$fake"
rm -f "$fake"
start_server

export PATCHSENSE_RELEASE_BASE="http://127.0.0.1:$port/releases/download"
export PATCHSENSE_CACHE_DIR="$cache"

out=$(php "$root/bin/patchsense" --version)
if [ "$out" != "fake-patchsense 0.1.0" ]; then
  echo "unexpected version: $out" >&2
  exit 1
fi

shell_cache=$(mktemp -d)
out=$(PATCHSENSE_CACHE_DIR="$shell_cache" "$root/scripts/fetch-release.sh" --version)
if [ "$out" != "fake-patchsense 0.1.0" ]; then
  echo "shell launcher version: $out" >&2
  exit 1
fi
set +e
PATCHSENSE_CACHE_DIR="$shell_cache" "$root/scripts/fetch-release.sh" --exit 3
shell_code=$?
set -e
if [ "$shell_code" -ne 3 ]; then
  echo "shell exit code was $shell_code, want 3" >&2
  exit 1
fi

args_out=$(php "$root/bin/patchsense" hello "two words")
if [ "$args_out" != "args:hello two words" ]; then
  echo "unexpected args: $args_out" >&2
  exit 1
fi

set +e
php "$root/bin/patchsense" --exit 3
code=$?
set -e
if [ "$code" -ne 3 ]; then
  echo "exit code was $code, want 3" >&2
  exit 1
fi

stop_server
out=$(php "$root/bin/patchsense" --version)
if [ "$out" != "fake-patchsense 0.1.0" ]; then
  echo "cached run failed offline: $out" >&2
  exit 1
fi

empty=$(mktemp -d)
export PATCHSENSE_CACHE_DIR="$empty"
set +e
offline_err=$(php "$root/bin/patchsense" --version 2>&1)
offline_code=$?
set -e
if [ "$offline_code" -ne 2 ]; then
  echo "uncached run exit code was $offline_code, want 2" >&2
  exit 1
fi
echo "$offline_err" | grep -q "download failed" || {
  echo "missing download error: $offline_err" >&2
  exit 1
}

start_server
python3 - <<PY
import json
p = "$stage/releases/download/v0.1.0/dist-manifest.json"
data = json.load(open(p))
for art in data["artifacts"].values():
    art["checksums"]["sha256"] = "0" * 64
json.dump(data, open(p, "w"))
PY
bad_cache=$(mktemp -d)
export PATCHSENSE_CACHE_DIR="$bad_cache"
set +e
bad_err=$(php "$root/bin/patchsense" --version 2>&1)
bad_code=$?
set -e
if [ "$bad_code" -eq 0 ]; then
  echo "bad checksum was accepted" >&2
  exit 1
fi
echo "$bad_err" | grep -q "checksum mismatch" || {
  echo "missing checksum error: $bad_err" >&2
  exit 1
}
if find "$bad_cache" -type f -name patchsense | grep -q .; then
  echo "bad checksum left a cached binary" >&2
  exit 1
fi
shell_bad=$(mktemp -d)
set +e
shell_bad_err=$(PATCHSENSE_CACHE_DIR="$shell_bad" "$root/scripts/fetch-release.sh" --version 2>&1)
shell_bad_code=$?
set -e
if [ "$shell_bad_code" -eq 0 ]; then
  echo "shell launcher accepted a bad checksum" >&2
  exit 1
fi
echo "$shell_bad_err" | grep -q "checksum mismatch" || {
  echo "shell checksum error: $shell_bad_err" >&2
  exit 1
}

if [ -x "$root/target/release/patchsense" ]; then
  pack_binary "$root/target/release/patchsense"
  real_cache=$(mktemp -d)
  export PATCHSENSE_CACHE_DIR="$real_cache"
  real=$(php "$root/bin/patchsense" --version)
  if [ "$real" != "patchsense 0.1.0" ]; then
    echo "real binary version: $real" >&2
    exit 1
  fi
fi

proj=$(mktemp -d)
(
  cd "$proj"
  export COMPOSER_DISABLE_NETWORK=1
  composer init --name=test/app --no-interaction --quiet
  composer config repositories.patchsense "{\"type\":\"path\",\"url\":\"$root\",\"options\":{\"symlink\":false}}"
  composer require --dev widyasa/patchsense:0.1.0 --no-interaction --no-progress
)
export PATCHSENSE_CACHE_DIR="$cache"
vendor_out=$("$proj/vendor/bin/patchsense" --version)
if [ "$vendor_out" != "fake-patchsense 0.1.0" ]; then
  echo "composer bin version: $vendor_out" >&2
  exit 1
fi
rm -rf "$proj"

echo "composer launcher ok"

override=$(mktemp)
cat > "$override" <<'EOF'
#!/bin/sh
echo "override-patchsense"
exit 0
EOF
chmod 0755 "$override"
override_out=$(
  PATCHSENSE_BINARY="$override" \
  PATCHSENSE_RELEASE_BASE="http://127.0.0.1:1" \
  PATCHSENSE_CACHE_DIR="$(mktemp -d)" \
  php "$root/bin/patchsense" --version
)
if [ "$override_out" != "override-patchsense" ]; then
  echo "php PATCHSENSE_BINARY: $override_out" >&2
  exit 1
fi
shell_override=$(
  PATCHSENSE_BINARY="$override" \
  PATCHSENSE_RELEASE_BASE="http://127.0.0.1:1" \
  "$root/scripts/fetch-release.sh" --version
)
if [ "$shell_override" != "override-patchsense" ]; then
  echo "shell PATCHSENSE_BINARY: $shell_override" >&2
  exit 1
fi
rm -f "$override"

empty_stage=$(mktemp -d)
port404=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
python3 -m http.server "$port404" --bind 127.0.0.1 --directory "$empty_stage" >"$log" 2>&1 &
server404=$!
i=0
while [ "$i" -lt 50 ]; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port404/releases/download/v0.1.0/dist-manifest.json" || true)
  if [ "$code" = "404" ]; then
    break
  fi
  i=$((i + 1))
  sleep 0.05
done
if [ "$code" != "404" ]; then
  echo "404 server did not start" >&2
  kill "$server404" 2>/dev/null || true
  exit 1
fi

assert_missing() {
  label=$1
  err=$2
  code=$3
  if [ "$code" -ne 2 ]; then
    echo "$label exit code was $code, want 2" >&2
    exit 1
  fi
  for phrase in "not published yet" "cargo install patchsense --locked" "building from source" "PATCHSENSE_BINARY=/path/to/patchsense"; do
    if ! printf '%s\n' "$err" | grep -q "$phrase"; then
      echo "$label missing '$phrase': $err" >&2
      exit 1
    fi
  done
}

set +e
php_err=$(
  PATCHSENSE_BINARY= \
  PATCHSENSE_RELEASE_BASE="http://127.0.0.1:$port404/releases/download" \
  PATCHSENSE_CACHE_DIR="$(mktemp -d)" \
  php "$root/bin/patchsense" --version 2>&1
)
php_code=$?
shell_err=$(
  PATCHSENSE_BINARY= \
  PATCHSENSE_RELEASE_BASE="http://127.0.0.1:$port404/releases/download" \
  PATCHSENSE_CACHE_DIR="$(mktemp -d)" \
  "$root/scripts/fetch-release.sh" --version 2>&1
)
shell_code=$?
set -e
kill "$server404" 2>/dev/null || true
wait "$server404" 2>/dev/null || true
rm -rf "$empty_stage"
assert_missing "php 404" "$php_err" "$php_code"
assert_missing "shell 404" "$shell_err" "$shell_code"
echo "missing release ok"

set +e
missing_php=$(PATCHSENSE_BINARY=/nope/patchsense php "$root/bin/patchsense" --version 2>&1)
missing_php_code=$?
missing_shell=$(PATCHSENSE_BINARY=/nope/patchsense "$root/scripts/fetch-release.sh" --version 2>&1)
missing_shell_code=$?
set -e
if [ "$missing_php_code" -ne 2 ] || [ "$missing_shell_code" -ne 2 ]; then
  echo "missing binary php=$missing_php_code shell=$missing_shell_code" >&2
  printf '%s\n' "$missing_php" "$missing_shell" >&2
  exit 1
fi
echo "missing binary ok"

(cd "$root" && go test -count=1 ./go/cmd/patchsense)
echo "go launcher ok"
