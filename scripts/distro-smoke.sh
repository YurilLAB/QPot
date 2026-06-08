#!/usr/bin/env bash
#
# distro-smoke.sh — prove the QPot binary actually RUNS on a matrix of Linux
# distributions, not just that it cross-compiles.
#
# The CI cross-build job confirms QPot *compiles* for linux/{amd64,arm64,arm},
# but a static binary can still fail to launch at runtime for reasons a compile
# never catches: a different libc (musl on Alpine vs glibc elsewhere), a missing
# dynamic loader, distro-specific /etc or PATH assumptions. This harness builds
# the binary once and executes its CLI smoke inside a real container for each
# distro, so a runtime-portability regression is caught here instead of on a
# user's machine.
#
# Images are pulled from mirrors that are NOT subject to Docker Hub's
# unauthenticated pull-rate limit, so the run is reproducible in CI.
#
# Usage:
#   scripts/distro-smoke.sh [path-to-qpot-binary]
#
# Env:
#   QPOT_DISTROS  space-separated override of the image list (optional)
#
# Requires: docker (a running daemon) and a CGO-free static linux/amd64 binary.

set -euo pipefail

BIN="${1:-./qpot}"

if [ ! -x "$BIN" ]; then
  echo "### binary not found or not executable: $BIN" >&2
  echo "### build it first, e.g.: CGO_ENABLED=0 go build -o qpot ./cmd/qpot" >&2
  exit 2
fi
BIN_ABS="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

if ! command -v docker >/dev/null 2>&1; then
  echo "### docker is required but not installed" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "### docker daemon is not reachable" >&2
  exit 2
fi

# Default matrix: glibc (Debian/Ubuntu/Fedora/Rocky/openSUSE) + musl (Alpine).
# Covers the four major packaging families QPot's installer targets plus the
# musl edge case that most often breaks a "static" Go binary.
default_distros=(
  "public.ecr.aws/docker/library/alpine:3.20"
  "public.ecr.aws/docker/library/debian:12-slim"
  "public.ecr.aws/docker/library/ubuntu:22.04"
  "quay.io/fedora/fedora:40"
  "quay.io/rockylinux/rockylinux:9"
  "registry.opensuse.org/opensuse/leap:15.6"
)

if [ -n "${QPOT_DISTROS:-}" ]; then
  read -r -a distros <<<"${QPOT_DISTROS}"
else
  distros=("${default_distros[@]}")
fi

# The smoke run executed inside each container. Mirrors the CLI checks the
# build-run CI job performs on Ubuntu, but here on every distro. HOME is a
# throwaway so instance state never escapes the container.
# shellcheck disable=SC2016  # intentional: this runs in the container, not here
smoke='
set -e
echo "[os] $(grep -E "^PRETTY_NAME=" /etc/os-release | cut -d= -f2 | tr -d \")"
qpot --version
qpot --help >/dev/null
qpot honeypot list >/dev/null
qpot instance create smoke >/dev/null
qpot instance list | grep -q smoke
echo "[pass] CLI smoke OK"
'

fail=0
passed=()
failed=()
for img in "${distros[@]}"; do
  name="${img##*/}"
  echo "============================================================"
  echo "DISTRO: $name  ($img)"
  echo "============================================================"
  if [ -z "${QPOT_SKIP_PULL:-}" ]; then
    if ! docker pull -q "$img" >/dev/null 2>&1; then
      echo "  ### pull failed for $img" >&2
      failed+=("$name(pull)")
      fail=1
      continue
    fi
  fi
  if docker run --rm \
    -v "$BIN_ABS:/usr/local/bin/qpot:ro" \
    -e HOME=/tmp \
    "$img" sh -c "$smoke" 2>&1 | sed 's/^/  /'; then
    passed+=("$name")
  else
    echo "  ### smoke FAILED on $name" >&2
    failed+=("$name")
    fail=1
  fi
done

echo "============================================================"
echo "SUMMARY: ${#passed[@]} passed, ${#failed[@]} failed"
[ "${#passed[@]}" -gt 0 ] && echo "  passed: ${passed[*]}"
[ "${#failed[@]}" -gt 0 ] && echo "  failed: ${failed[*]}"
echo "============================================================"

exit "$fail"
