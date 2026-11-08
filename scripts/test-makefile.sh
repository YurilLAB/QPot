#!/usr/bin/env bash
# Exercise Makefile failure handling with controlled tools in temporary directories.
# These fixtures do not compile QPot; the Go tests and CI validate the application.
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# The version the Makefile names its release archives with.
ver=$(sed -n 's/^VERSION ?= \([^[:space:]]*\)[[:space:]]*$/\1/p' "$repo_dir/Makefile")
[ -n "$ver" ] || { echo "no VERSION in the Makefile"; exit 2; }
make_bin=$(command -v make)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
checks=0
failures=0
case_dir=
tool_dir=

new_case() {
  case_dir="$tmp_dir/case-$checks"
  tool_dir="$case_dir/tools"
  mkdir -p "$tool_dir"
  cp "$repo_dir/Makefile" "$case_dir/Makefile"
  # A controlled PATH makes missing-scanner checks independent of host tools.
  local tool
  for tool in sh mkdir cut date grep tar gzip zip; do
    ln -s "$(command -v "$tool")" "$tool_dir/$tool"
  done
  cat > "$tool_dir/go" <<'SH'
#!/bin/sh
printf 'go %s %s/%s\n' "$*" "${GOOS:-}" "${GOARCH:-}" >> "$QPOT_TEST_TOOL_LOG"
if [ "${1:-}" != build ]; then
  exit 0
fi
if [ "${QPOT_TEST_FAIL_BUILD:-}" = "${GOOS:-}/${GOARCH:-}" ]; then
  echo "injected build failure" >&2
  exit 23
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then
    shift
    printf 'test binary for %s/%s\n' "$GOOS" "$GOARCH" > "$1"
    exit 0
  fi
  shift
done
exit 1
SH
  chmod +x "$tool_dir/go"
}

add_scanner() {
  cat > "$tool_dir/$1" <<'SH'
#!/bin/sh
tool=${0##*/}
printf '%s %s\n' "$tool" "$*" >> "$QPOT_TEST_TOOL_LOG"
if [ "${QPOT_TEST_FAIL_TOOL:-}" = "$tool" ]; then
  echo "injected scanner failure" >&2
  exit 31
fi
SH
  chmod +x "$tool_dir/$1"
}

fail_packager() {
  # Remove the link before writing, so the real system executable stays intact.
  rm "$tool_dir/$1"
  cat > "$tool_dir/$1" <<'SH'
#!/bin/sh
echo "injected packaging failure" >&2
exit 37
SH
  chmod +x "$tool_dir/$1"
}

run_make() {
  (cd "$case_dir" && PATH="$tool_dir" MAKEFLAGS='' \
    QPOT_TEST_TOOL_LOG="$case_dir/tools.log" \
    "$make_bin" -s "$@") > "$case_dir/output.log" 2>&1
}

build_failure() {
  if QPOT_TEST_FAIL_BUILD=linux/amd64 run_make build-all; then
    return 1
  fi
  ! grep -q 'Built all platforms' "$case_dir/output.log"
}

release_build_failure() {
  if QPOT_TEST_FAIL_BUILD=linux/amd64 run_make release; then
    return 1
  fi
  ! grep -q 'Creating release archives' "$case_dir/output.log"
}

repeat_release() {
  run_make release 'PLATFORMS=linux/amd64 windows/amd64' || return 1
  run_make release 'PLATFORMS=linux/amd64 windows/amd64' || return 1
  local files=("$case_dir"/dist/*)
  [ "${#files[@]}" -eq 4 ] || return 1
  [ "$(tar tzf "$case_dir/dist/qpot_${ver}_linux_amd64.tar.gz")" = "qpot_${ver}_linux_amd64" ] || return 1
  [ "$(unzip -Z1 "$case_dir/dist/qpot_${ver}_windows_amd64.zip")" = "qpot_${ver}_windows_amd64.exe" ]
}

packaging_failure() {
  local packager=$1 platforms=$2
  fail_packager "$packager"
  if run_make release "PLATFORMS=$platforms"; then
    return 1
  fi
  ! grep -q 'Created release archives' "$case_dir/output.log"
}

missing_linter() {
  add_scanner govulncheck
  if run_make ci; then
    return 1
  fi
  grep -q 'golangci-lint not installed' "$case_dir/output.log"
}

missing_scanner() {
  add_scanner golangci-lint
  if run_make ci; then
    return 1
  fi
  grep -q 'govulncheck not installed' "$case_dir/output.log"
}

all_checks_present() {
  add_scanner golangci-lint
  add_scanner govulncheck
  run_make ci || return 1
  grep -q '^golangci-lint run$' "$case_dir/tools.log" || return 1
  grep -q '^govulncheck ./\.\.\.$' "$case_dir/tools.log" || return 1
  grep -q 'All CI checks passed' "$case_dir/output.log"
}

scanner_failure() {
  add_scanner golangci-lint
  add_scanner govulncheck
  if QPOT_TEST_FAIL_TOOL="$1" run_make ci; then
    return 1
  fi
  ! grep -q 'All CI checks passed' "$case_dir/output.log"
}

check() {
  local name=$1
  shift
  checks=$((checks + 1))
  new_case
  if "$@"; then
    printf 'PASS: %s\n' "$name"
  else
    printf 'FAIL: %s\n' "$name"
    cat "$case_dir/output.log"
    failures=$((failures + 1))
  fi
}

check 'build-all propagates an early compiler failure' build_failure
check 'release stops after a failed platform build' release_build_failure
check 'repeated releases only contain intended binary archives' repeat_release
check 'release propagates tar failure before a later successful archive' packaging_failure tar 'linux/amd64 windows/amd64'
check 'release propagates zip failure' packaging_failure zip 'windows/amd64 linux/amd64'
check 'ci fails when the linter is missing' missing_linter
check 'ci fails when the vulnerability scanner is missing' missing_scanner
check 'ci runs both tools when present' all_checks_present
check 'ci propagates a linter failure' scanner_failure golangci-lint
check 'ci propagates a vulnerability scanner failure' scanner_failure govulncheck
printf '%d/%d Makefile regression checks passed\n' "$((checks - failures))" "$checks"
[ "$failures" -eq 0 ]
