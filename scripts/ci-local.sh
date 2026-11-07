#!/usr/bin/env bash
# Run the checks of .github/workflows/ci.yml on this machine, so a local pass
# means the same as a CI pass. The jobs' own run: scripts are executed, in
# order and with the same environment (internal/cicheck/cirun reads the
# workflow), with the tool versions and gosec exclude list CI loads from
# .github/ci-tools.env. Nothing is copied from the workflow into this script.
#
# Usage: scripts/ci-local.sh [--list] [--only job,job] [--skip job,job] [--no-docker]
#   --list       print the jobs and exit
#   --only       run only these jobs
#   --skip       do not run these jobs (reported as SKIPPED)
#   --no-docker  skip the jobs that need Docker (service containers or
#                scripts/distro-smoke.sh)
#
# It runs on Linux (x86_64, as CI does; WSL works). Tools CI installs with
# `go install` are installed at the pinned versions into a cache under
# ${XDG_CACHE_HOME:-~/.cache}/qpot-ci-local, not into your own GOPATH.
# A tool that is missing (go, docker, Python 3.11 for the connector job, or
# a program CI's runner has preinstalled, such as a C compiler for -race or
# PyYAML) fails its job with a message naming it; only --skip/--no-docker skip.
# Jobs that run on Windows in CI are reported as NOT RUN here; run
# scripts/test-install.ps1 on Windows for those.
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo" || exit 2

only="" skip="" list=0
while [ $# -gt 0 ]; do
  case $1 in
    --list) list=1 ;;
    --only) only=",${2:?--only needs job names},"; shift ;;
    --skip) skip="${skip},${2:?--skip needs job names},"; shift ;;
    --no-docker) skip="${skip},clickhouse-integration,distro-runtime," ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "ci-local: unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

case "$(uname -s)" in
  Linux) ;;
  *) echo "ci-local: CI runs on Linux; run this in Linux or WSL" >&2; exit 2 ;;
esac
command -v go >/dev/null || { echo "ci-local: go is not installed" >&2; exit 2; }

cache="${XDG_CACHE_HOME:-$HOME/.cache}/qpot-ci-local"
mkdir -p "$cache/gopath" || exit 2
# Keep the module cache shared (downloads are checked against go.sum), but
# install CI's pinned tools into our own GOPATH: `go env GOPATH`/bin is where
# the workflow's scripts look for them.
GOMODCACHE=$(go env GOMODCACHE)
export GOMODCACHE GOPATH="$cache/gopath"
cirun="$cache/cirun"
go build -o "$cirun" ./internal/cicheck/cirun || { echo "ci-local: could not build the runner" >&2; exit 2; }

mapfile -t jobs < <("$cirun" -root "$repo" list) || exit 2
if [ "$list" = 1 ]; then
  printf '%s\n' "${jobs[@]}"
  exit 0
fi
"$cirun" -root "$repo" check || { echo "ci-local: the workflow uses something ci-local cannot run; update internal/cicheck" >&2; exit 2; }

# Jobs that need Docker: service containers, or the distro smoke script.
needs_docker() { [ "$2" = docker ] || [ "$1" = distro-runtime ]; }

# Programs a job's scripts use that CI's ubuntu runner has preinstalled
# (Go, Docker and Python 3.11 are checked where the job sets them up).
# python3:yaml means python3 with PyYAML. A missing one fails the job here,
# by name, instead of half-way through it.
job_tools() {
  case $1 in
    # -race needs a C compiler: $CC (its first word) or cc.
    build-test) cc=${CC:-cc}; echo "python3 make curl git setsid timeout tar gzip ${cc%% *}" ;;
    build-run) echo "python3:yaml timeout" ;;
    gitleaks|mod-hygiene) echo "git" ;;
    shellcheck|actionlint) echo "curl tar xz sha256sum" ;;
    coverage) echo "awk" ;;
  esac
}
missing_tools() {
  local t miss=""
  for t in $(job_tools "$1"); do
    case $t in
      python3:yaml) python3 -c 'import yaml' >/dev/null 2>&1 || miss="$miss python3-yaml(PyYAML)" ;;
      *) command -v "$t" >/dev/null 2>&1 || miss="$miss $t" ;;
    esac
  done
  printf '%s' "${miss# }"
}

declare -a results
failed=0
for line in "${jobs[@]}"; do
  IFS=$'\t' read -r id runs_on need <<<"$line"
  if [ -n "$only" ] && [[ $only != *",$id,"* ]]; then continue; fi
  if [[ $skip == *",$id,"* ]]; then results+=("SKIPPED  $id (by flag)"); continue; fi
  if [[ $runs_on != ubuntu-* ]]; then
    results+=("NOT RUN  $id (CI runs it on $runs_on)")
    continue
  fi
  miss=$(missing_tools "$id")
  if [ -n "$miss" ]; then
    results+=("FAIL     $id (needs $miss, which CI's runner has and this machine lacks; install it, or pass --skip $id)")
    failed=1
    continue
  fi
  if needs_docker "$id" "$need" && ! docker info >/dev/null 2>&1; then
    results+=("FAIL     $id (needs Docker, which is not running; or pass --no-docker)")
    failed=1
    continue
  fi
  echo
  echo "################ $id"
  start=$(date +%s)
  if "$cirun" -root "$repo" run "$id"; then
    results+=("PASS     $id ($(( $(date +%s) - start ))s)")
  else
    results+=("FAIL     $id ($(( $(date +%s) - start ))s)")
    failed=1
  fi
done

echo
echo "################ ci-local summary"
printf '  %s\n' "${results[@]}"
exit "$failed"
