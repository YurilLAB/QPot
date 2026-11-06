#!/usr/bin/env bash
# Exercise scripts/install.sh with controlled tools in temporary directories:
# every failure must print its QP- error code and exit with the code's
# category status, and a good install must hand over to `qpot setup`.
# Nothing is downloaded or installed outside the temporary directory.
# The fake programs are written as single-quoted shell text on purpose: they
# expand their variables when they run, not here.
# shellcheck disable=SC2016
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash_bin=$(command -v bash)
setsid_bin=$(command -v setsid || true)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
checks=0
failures=0
case_dir=
tool_dir=
rc=0

new_case() {
  case_dir="$tmp_dir/case-$checks"
  tool_dir="$case_dir/tools"
  mkdir -p "$tool_dir" "$case_dir/home"
  # A controlled PATH: only the tools the installer needs, plus fakes.
  local tool
  for tool in tr mktemp tar gzip rm mkdir cp chmod grep dirname awk sed cat sh; do
    ln -s "$(command -v "$tool")" "$tool_dir/$tool"
  done
  fake uname 'case "$1" in -s) echo "${FAKE_OS:-Linux}";; -m) echo "${FAKE_ARCH:-x86_64}";; esac'
  # curl serves a release archive holding a fake qpot, unless told to fail.
  fake curl '[ -n "${FAKE_NO_RELEASE:-}" ] && exit 22
out=""
while [ "$#" -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
mkdir -p "$QPOT_TEST_DIR/pkg"
printf "#!/bin/sh\n[ \"\$1\" = --version ] && { [ -n \"\${FAKE_BROKEN_QPOT:-}\" ] && exit 1; echo qpot 0.1.0; exit 0; }\necho \"qpot \$*\" >> \"$QPOT_TEST_DIR/qpot.log\"\nexit \${FAKE_SETUP_RC:-0}\n" > "$QPOT_TEST_DIR/pkg/qpot"
chmod +x "$QPOT_TEST_DIR/pkg/qpot"
tar -czf "$out" -C "$QPOT_TEST_DIR/pkg" qpot'
}

# fake NAME BODY writes a logging fake program into the case's tool dir.
fake() {
  printf '#!/bin/sh\necho "%s $*" >> "$QPOT_TEST_DIR/tools.log"\n%s\n' "$1" "$2" > "$tool_dir/$1"
  chmod +x "$tool_dir/$1"
}

# run_install runs the installer without a controlling terminal, as CI and
# `curl | bash` without a TTY do.
run_install() {
  rc=0
  (cd "$case_dir" && env -i PATH="$tool_dir" HOME="$case_dir/home" SHELL=/bin/false QPOT_TEST_DIR="$case_dir" "$@" \
    "$setsid_bin" "$bash_bin" "$repo_dir/scripts/install.sh") > "$case_dir/output.log" 2>&1 </dev/null || rc=$?
}

expect_code() {
  local code=$1 status=$2
  grep -q "ERROR ${code}:" "$case_dir/output.log" || return 1
  [ "$rc" -eq "$status" ] || { echo "exit status $rc, want $status"; return 1; }
  # One failure, one message: the catch-all must not fire as well.
  if [ "$code" != QP-BUG-002 ] && grep -q 'QP-BUG-002' "$case_dir/output.log"; then
    echo "the catch-all error was printed too"; return 1
  fi
}

unsupported_os() { run_install FAKE_OS=FreeBSD; expect_code QP-HOST-001 11; }
unsupported_arch() { run_install FAKE_ARCH=armv7l; expect_code QP-HOST-002 11; }

no_release_no_go() { run_install FAKE_NO_RELEASE=1; expect_code QP-HOST-006 11; }

old_go() {
  fake go 'echo "go version go1.19.2 linux/amd64"'
  fake git 'exit 0'
  run_install FAKE_NO_RELEASE=1
  expect_code QP-HOST-006 11 && grep -q 'Go 1.19.2 is too old' "$case_dir/output.log"
}

clone_fails() {
  fake go 'echo "go version go1.26.0 linux/amd64"'
  fake git 'echo "fatal: unable to access" >&2; exit 128'
  run_install FAKE_NO_RELEASE=1
  expect_code QP-NET-007 13
}

build_fails() {
  fake go '[ "$1" = version ] && { echo "go version go1.26.0 linux/amd64"; exit 0; }; echo "build failed" >&2; exit 1'
  fake git 'for a; do d=$a; done; mkdir -p "$d"'
  run_install FAKE_NO_RELEASE=1
  expect_code QP-HOST-008 11
}

broken_binary() { run_install FAKE_BROKEN_QPOT=1; expect_code QP-HOST-007 11; }

unwritable_install_dir() {
  mkdir -p "$case_dir/home/.local"
  : > "$case_dir/home/.local/bin" # a file where the folder must go
  run_install
  expect_code QP-PERM-007 12
}

good_install_no_setup() {
  run_install QPOT_NO_SETUP=1
  [ "$rc" -eq 0 ] || return 1
  [ -x "$case_dir/home/.local/bin/qpot" ] || return 1
  grep -q 'Next: set up your first honeypot' "$case_dir/output.log" || return 1
  grep -q 'Docker is not installed yet' "$case_dir/output.log" || return 1
  # It no longer creates an instance behind setup's back.
  [ ! -e "$case_dir/qpot.log" ]
}

no_terminal_says_what_next() {
  run_install
  [ "$rc" -eq 0 ] || return 1
  grep -q "Run 'qpot setup'" "$case_dir/output.log" && [ ! -e "$case_dir/qpot.log" ]
}

hand_off_with_args() {
  run_install 'QPOT_SETUP_ARGS=--yes --install-docker'
  [ "$rc" -eq 0 ] || return 1
  grep -qx 'qpot setup --yes --install-docker' "$case_dir/qpot.log"
}

hand_off_passes_setup_status() {
  run_install 'QPOT_SETUP_ARGS=--yes' FAKE_SETUP_RC=15
  [ "$rc" -eq 15 ]
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

[ -n "$setsid_bin" ] || { echo "setsid (util-linux) is required"; exit 2; }
check 'an unsupported OS is QP-HOST-001 (exit 11)' unsupported_os
check 'an unsupported processor is QP-HOST-002 (exit 11)' unsupported_arch
check 'no release and no Go is QP-HOST-006 (exit 11)' no_release_no_go
check 'an old Go is QP-HOST-006' old_go
check 'a failed clone is QP-NET-007 (exit 13)' clone_fails
check 'a failed build is QP-HOST-008' build_fails
check 'a binary that does not run is QP-HOST-007' broken_binary
check 'an unwritable install folder is QP-PERM-007 (exit 12)' unwritable_install_dir
check 'a good install with QPOT_NO_SETUP=1 only installs' good_install_no_setup
check 'without a terminal it says what to run next' no_terminal_says_what_next
check 'QPOT_SETUP_ARGS hands over to qpot setup' hand_off_with_args
check 'the hand-over passes on qpot setup exit status' hand_off_passes_setup_status
printf '%d/%d install script checks passed\n' "$((checks - failures))" "$checks"
[ "$failures" -eq 0 ]
