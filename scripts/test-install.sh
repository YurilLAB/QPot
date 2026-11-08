#!/usr/bin/env bash
# Exercise scripts/install.sh against a real local release server (the
# qpot-release test-server: good and tampered releases on two loopback
# origins) with real curl, tar and sha256sum, in temporary directories:
# every failure must print its QP- error code, exit with the code's category
# status and install nothing; a good install must hand over to `qpot setup`.
# Nothing is downloaded from or installed to anywhere outside the temporary
# directory. Needs Go (to build the server), curl and util-linux's setsid.
# The fake programs are written as single-quoted shell text on purpose: they
# expand their variables when they run, not here.
# shellcheck disable=SC2016
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# The version install.sh downloads; the fake release carries the same.
ver=$(sed -n 's/^QPOT_VERSION="\([^"]*\)"$/\1/p' "$repo_dir/scripts/install.sh")
[ -n "$ver" ] || { echo "no QPOT_VERSION in scripts/install.sh"; exit 2; }
bash_bin=$(command -v bash)
setsid_bin=$(command -v setsid || true)
timeout_bin=$(command -v timeout || true)
tmp_dir=$(mktemp -d)
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
checks=0
failures=0
case_dir=
tool_dir=
rc=0

for need in go curl git; do
  command -v "$need" >/dev/null || { echo "$need is required"; exit 2; }
done
[ -n "$setsid_bin" ] || { echo "setsid (util-linux) is required"; exit 2; }
[ -n "$timeout_bin" ] || { echo "timeout (coreutils) is required"; exit 2; }

# The fake qpot the release archives carry: --version answers (unless told
# to fail), anything else is logged as a hand-over.
cat > "$tmp_dir/fake-qpot" <<'EOF'
#!/bin/sh
[ "$1" = --version ] && { [ -n "${FAKE_BROKEN_QPOT:-}" ] && exit 1; echo qpot test build; exit 0; }
echo "qpot $*" >> "$QPOT_TEST_DIR/qpot.log"
exit ${FAKE_SETUP_RC:-0}
EOF
chmod +x "$tmp_dir/fake-qpot"

(cd "$repo_dir" && go build -o "$tmp_dir/qpot-release" ./cmd/qpot-release)
"$tmp_dir/qpot-release" test-server -version "$ver" -unix-qpot "$tmp_dir/fake-qpot" \
  -ready "$tmp_dir/ready" -log "$tmp_dir/requests.log" -lifetime 15m &
server_pid=$!
for _ in $(seq 1 600); do [ -s "$tmp_dir/ready" ] && break; sleep 0.1; done
origin_a=$(sed -n 's/^A=//p' "$tmp_dir/ready")
origin_b=$(sed -n 's/^B=//p' "$tmp_dir/ready")
if [ -z "$origin_a" ] || [ -z "$origin_b" ]; then echo "the release server did not start"; exit 2; fi

# A git repository holding a tiny qpot, for the source build.
src_repo="$tmp_dir/src-repo"
mkdir -p "$src_repo/cmd/qpot"
printf 'module example.com/fakeqpot\n\ngo 1.21\n' > "$src_repo/go.mod"
cat > "$src_repo/cmd/qpot/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("qpot test build (built from source)")
		return
	}
	f, err := os.OpenFile(os.Getenv("QPOT_TEST_DIR")+"/qpot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		fmt.Fprintln(f, "qpot", os.Args[1:])
		f.Close()
	}
}
EOF
git -C "$src_repo" init -q
git -C "$src_repo" -c user.name=test -c user.email=test@example.invalid add -A
git -C "$src_repo" -c user.name=test -c user.email=test@example.invalid commit -q -m "fake qpot"
src_commit=$(git -C "$src_repo" rev-parse HEAD)
# The toolchain go.mod selects (with GOTOOLCHAIN switching, `command -v go`
# may be an older go that runs it), so the source build uses one Go only.
go_root=$(go env GOROOT)
go_bin="$go_root/bin/go"

new_case() {
  case_dir="$tmp_dir/case-$checks"
  tool_dir="$case_dir/tools"
  mkdir -p "$tool_dir" "$case_dir/home" "$case_dir/tmp"
  # A controlled PATH: only the tools the installer needs, plus fakes.
  local tool
  for tool in tr mktemp tar gzip rm mkdir cp chmod grep dirname awk sed cat sh mv wc tail env curl sha256sum; do
    ln -s "$(command -v "$tool")" "$tool_dir/$tool"
  done
  fake uname 'case "$1" in -s) echo "${FAKE_OS:-Linux}";; -m) echo "${FAKE_ARCH:-x86_64}";; esac'
  : > "$tmp_dir/requests.log"
}

# fake NAME BODY writes a logging fake program into the case's tool dir.
fake() {
  printf '#!/bin/sh\necho "%s $*" >> "$QPOT_TEST_DIR/tools.log"\n%s\n' "$1" "$2" > "$tool_dir/$1"
  chmod +x "$tool_dir/$1"
}

# real NAME links a real program into the case's tool dir.
real() { ln -sf "$(command -v "$1")" "$tool_dir/$1"; }

# run_install SCENARIO [VAR=value...] runs the installer against a scenario
# of the release server, without a controlling terminal, as CI and
# `curl | bash` without a TTY do. INSTALLER picks another copy of it.
installer="$repo_dir/scripts/install.sh"
run_install() {
  local scenario=$1
  shift
  rc=0
  (cd "$case_dir" && env -i PATH="$tool_dir" HOME="$case_dir/home" TMPDIR="$case_dir/tmp" SHELL=/bin/false \
    QPOT_TEST_DIR="$case_dir" QPOT_DOWNLOAD_BASE="$origin_a/$scenario" "$@" \
    "$timeout_bin" 300 "$setsid_bin" "$bash_bin" "$installer") > "$case_dir/output.log" 2>&1 </dev/null || rc=$?
}
pinned=$(sed -n 's/^QPOT_SOURCE_COMMIT_PINNED="\([0-9a-f]*\)"$/\1/p' "$repo_dir/scripts/install.sh")
[[ $pinned =~ ^[0-9a-f]{40}$ ]] || { echo "install.sh pins no source commit"; exit 2; }
# A copy without the pin: an installer that has nothing it can build.
sed 's/^QPOT_SOURCE_COMMIT_PINNED=.*/QPOT_SOURCE_COMMIT_PINNED=""/' "$repo_dir/scripts/install.sh" > "$tmp_dir/install-nopin.sh"

expect_code() {
  local code=$1 status=$2
  grep -q "ERROR ${code}:" "$case_dir/output.log" || return 1
  [ "$rc" -eq "$status" ] || { echo "exit status $rc, want $status"; return 1; }
  # One failure, one message: the catch-all must not fire as well.
  if [ "$code" != QP-BUG-002 ] && grep -q 'QP-BUG-002' "$case_dir/output.log"; then
    echo "the catch-all error was printed too"; return 1
  fi
}

# nothing_installed: no program, no hand-over, and the temp folder is gone.
nothing_installed() {
  [ ! -e "$case_dir/home/.local/bin/qpot" ] || { echo "qpot was installed"; return 1; }
  [ ! -e "$case_dir/qpot.log" ] || { echo "setup was started"; return 1; }
  [ -z "$(ls -A "$case_dir/tmp")" ] || { echo "temp files left: $(ls -A "$case_dir/tmp")"; return 1; }
}

installed() {
  [ "$rc" -eq 0 ] || { echo "exit status $rc"; return 1; }
  "$case_dir/home/.local/bin/qpot" --version >/dev/null || return 1
  [ -z "$(ls -A "$case_dir/tmp")" ] || { echo "temp files left"; return 1; }
}

unsupported_os() { run_install good FAKE_OS=FreeBSD; expect_code QP-HOST-001 11; }
unsupported_arch() { run_install good FAKE_ARCH=armv7l; expect_code QP-HOST-002 11; }

good_release() {
  run_install good QPOT_NO_SETUP=1
  installed || return 1
  grep -q 'Checksum matches SHA256SUMS' "$case_dir/output.log" || return 1
  grep -q 'Build provenance not checked' "$case_dir/output.log" || return 1
  grep -q "^A /good/v${ver}/qpot_${ver}_linux_amd64.tar.gz$" "$tmp_dir/requests.log" || return 1
  ! grep -q '^B ' "$tmp_dir/requests.log"
}

good_release_arm64() {
  run_install good QPOT_NO_SETUP=1 FAKE_ARCH=aarch64
  installed && grep -q "^A /good/v${ver}/qpot_${ver}_linux_arm64.tar.gz$" "$tmp_dir/requests.log"
}

# GitHub answers a release download with a redirect to its asset server.
same_origin_redirect() {
  run_install redirect-same QPOT_NO_SETUP=1
  installed && grep -q "^A /good/v${ver}/qpot_${ver}_linux_amd64.tar.gz$" "$tmp_dir/requests.log"
}

tampered_archive() { run_install tampered-archive; expect_code QP-NET-009 13 && nothing_installed; }
tampered_sums() { run_install tampered-sums; expect_code QP-NET-009 13 && nothing_installed; }
malformed_sums() {
  run_install malformed-sums
  expect_code QP-NET-010 13 && nothing_installed && grep -q 'SHA256SUMS) is not valid' "$case_dir/output.log"
}
big_sums() {
  run_install big-sums
  expect_code QP-NET-010 13 && nothing_installed && grep -q 'SHA256SUMS) is not valid' "$case_dir/output.log"
}
no_entry() {
  run_install no-entry
  expect_code QP-NET-010 13 && nothing_installed && grep -q "no entry for qpot_${ver}_linux_amd64.tar.gz" "$case_dir/output.log"
}

# The server promises the whole file and sends half: curl notices.
truncated() { run_install truncated; expect_code QP-NET-007 13 && nothing_installed; }
# The server ends the connection half-way without a length: to curl the
# download looks complete, and only the checksum shows it is not.
short_body() { run_install short-body; expect_code QP-NET-009 13 && nothing_installed; }

other_origin_redirect() {
  run_install redirect-other
  expect_code QP-NET-011 13 && nothing_installed || return 1
  # Refused before connecting: origin B never saw a request.
  if grep -q '^B ' "$tmp_dir/requests.log"; then echo "origin B was contacted"; return 1; fi
}

# ~/.curlrc could tell curl to follow redirects itself (-L) or to skip
# certificate checks (-k); the installer must ignore it.
curlrc_ignored() {
  printf 'location\ninsecure\nmax-redirs = 50\n' > "$case_dir/home/.curlrc"
  run_install redirect-other
  expect_code QP-NET-011 13 && nothing_installed && ! grep -q '^B ' "$tmp_dir/requests.log"
}

other_host_redirect() {
  run_install redirect-host
  expect_code QP-NET-011 13 && nothing_installed && grep -q 'redirected to http://localhost:' "$case_dir/output.log" || return 1
  if grep -q '^B ' "$tmp_dir/requests.log"; then echo "origin B was contacted"; return 1; fi
}

redirect_loop() { run_install redirect-loop; expect_code QP-NET-007 13 && nothing_installed && grep -q 'too many redirects' "$case_dir/output.log"; }

http_base_refused() {
  rc=0
  (cd "$case_dir" && env -i PATH="$tool_dir" HOME="$case_dir/home" TMPDIR="$case_dir/tmp" SHELL=/bin/false \
    QPOT_TEST_DIR="$case_dir" QPOT_DOWNLOAD_BASE="http://example.invalid/releases" \
    "$timeout_bin" 300 "$setsid_bin" "$bash_bin" "$repo_dir/scripts/install.sh") > "$case_dir/output.log" 2>&1 </dev/null || rc=$?
  expect_code QP-INPUT-012 10 && nothing_installed
}

no_curl() { rm "$tool_dir/curl"; run_install good; expect_code QP-HOST-011 11 && nothing_installed; }
no_checksum_tool() { rm "$tool_dir/sha256sum"; run_install good; expect_code QP-HOST-010 11 && nothing_installed; }
shasum_only() {
  rm "$tool_dir/sha256sum"
  real shasum
  run_install good QPOT_NO_SETUP=1
  installed && grep -q 'Checksum matches' "$case_dir/output.log"
}

# The GitHub CLI checks the provenance; the fake records what it was asked.
fake_gh() {
  fake gh 'if [ "$1 $2 $3" = "attestation verify --help" ]; then
  echo "  -b, --bundle string"; echo "      --deny-self-hosted-runners"
  echo "      --signer-workflow string"; [ -n "${FAKE_GH_OLD:-}" ] || echo "      --source-ref string"
  exit 0
fi
printf "%s\n" "$@" > "$QPOT_TEST_DIR/gh-args"
exit ${FAKE_GH_RC:-0}'
}

provenance_verified() {
  fake_gh
  run_install good QPOT_NO_SETUP=1
  installed && grep -q 'Build provenance verified' "$case_dir/output.log" || return 1
  local want
  for want in attestation verify --bundle --repo YurilLAB/QPot --signer-workflow \
    YurilLAB/QPot/.github/workflows/release.yml --source-ref "refs/tags/v${ver}" --deny-self-hosted-runners; do
    grep -qx -- "$want" "$case_dir/gh-args" || { echo "gh was not given $want"; return 1; }
  done
  grep -q "/qpot_${ver}_provenance.sigstore.json$" "$case_dir/gh-args"
}

provenance_rejected() { fake_gh; run_install good FAKE_GH_RC=1; expect_code QP-NET-012 13 && nothing_installed; }
provenance_missing() { fake_gh; run_install no-provenance; expect_code QP-NET-012 13 && nothing_installed; }
provenance_required() { run_install good QPOT_REQUIRE_PROVENANCE=1; expect_code QP-NET-012 13 && nothing_installed; }

# A gh too old to pin the tag (no --source-ref) is not asked: it would
# accept a build from any ref of the repository.
old_gh_not_used() {
  fake_gh
  run_install good QPOT_NO_SETUP=1 FAKE_GH_OLD=1
  installed && grep -q 'Build provenance not checked' "$case_dir/output.log" && [ ! -e "$case_dir/gh-args" ]
}
old_gh_required() {
  fake_gh
  run_install good QPOT_REQUIRE_PROVENANCE=1 FAKE_GH_OLD=1
  expect_code QP-NET-012 13 && nothing_installed && grep -q 'too old' "$case_dir/output.log"
}

no_release_no_pin() {
  installer="$tmp_dir/install-nopin.sh" run_install missing-sums
  expect_code QP-NET-013 13 && nothing_installed
}

# Without QPOT_SOURCE_COMMIT the installer builds the commit it pins (the
# test repository does not have it, so the fetch fails, naming it).
source_default_is_pin() {
  real git
  ln -s "$go_bin" "$tool_dir/go"
  run_install missing-sums QPOT_SOURCE_REPO="$src_repo" GOTOOLCHAIN=local GOPROXY=off GOROOT="$go_root"
  expect_code QP-NET-007 13 && nothing_installed && grep -q "commit ${pinned} from" "$case_dir/output.log"
}

source_env() { printf '%s\n' QPOT_SOURCE_REPO="$src_repo" QPOT_SOURCE_COMMIT="$src_commit" \
  GOCACHE="$tmp_dir/gocache" GOPATH="$tmp_dir/gopath" GOTOOLCHAIN=local GOPROXY=off GOROOT="$go_root"; }

source_build() {
  real git
  ln -s "$go_bin" "$tool_dir/go"
  local -a e
  mapfile -t e < <(source_env)
  run_install missing-sums QPOT_NO_SETUP=1 "${e[@]}"
  installed && grep -q 'Built QPot from source' "$case_dir/output.log" &&
    "$case_dir/home/.local/bin/qpot" --version | grep -q 'built from source'
}

source_commit_unknown() {
  real git
  ln -s "$go_bin" "$tool_dir/go"
  local -a e
  mapfile -t e < <(source_env)
  run_install missing-sums "${e[@]}" QPOT_SOURCE_COMMIT="$(printf '%040d' 1)"
  expect_code QP-NET-007 13 && nothing_installed
}

# A git that reports another commit than the pinned one (a fetch that did
# not get what was asked for) stops the build.
source_commit_mismatch() {
  local real_git
  real_git=$(command -v git)
  fake git 'if [ "$3 $4" = "rev-parse HEAD" ]; then echo 0000000000000000000000000000000000000002; exit 0; fi
exec '"$real_git"' "$@"'
  ln -s "$go_bin" "$tool_dir/go"
  local -a e
  mapfile -t e < <(source_env)
  run_install missing-sums "${e[@]}"
  expect_code QP-NET-014 13 && nothing_installed && grep -q "pins ${src_commit}" "$case_dir/output.log"
}

source_no_go() {
  run_install missing-sums QPOT_SOURCE_COMMIT="$src_commit"
  expect_code QP-HOST-006 11 && nothing_installed
}

old_go() {
  fake go 'echo "go version go1.19.2 linux/amd64"'
  fake git 'exit 0'
  run_install missing-sums QPOT_SOURCE_COMMIT="$src_commit"
  expect_code QP-HOST-006 11 && grep -q 'Go 1.19.2 is too old' "$case_dir/output.log"
}

build_fails() {
  fake go '[ "$1" = version ] && { echo "go version go1.26.0 linux/amd64"; exit 0; }; echo "build failed" >&2; exit 1'
  real git
  run_install missing-sums QPOT_SOURCE_REPO="$src_repo" QPOT_SOURCE_COMMIT="$src_commit"
  expect_code QP-HOST-008 11 && nothing_installed
}

broken_binary() { run_install good FAKE_BROKEN_QPOT=1; expect_code QP-HOST-007 11; }

unwritable_install_dir() {
  mkdir -p "$case_dir/home/.local"
  : > "$case_dir/home/.local/bin" # a file where the folder must go
  run_install good
  expect_code QP-PERM-007 12
}

good_install_no_setup() {
  run_install good QPOT_NO_SETUP=1
  installed || return 1
  grep -q 'Next: set up your first honeypot' "$case_dir/output.log" || return 1
  grep -q 'Docker is not installed yet' "$case_dir/output.log" || return 1
  # It no longer creates an instance behind setup's back.
  [ ! -e "$case_dir/qpot.log" ]
}

no_terminal_says_what_next() {
  run_install good
  [ "$rc" -eq 0 ] || return 1
  grep -q "Run 'qpot setup'" "$case_dir/output.log" && [ ! -e "$case_dir/qpot.log" ]
}

hand_off_with_args() {
  run_install good 'QPOT_SETUP_ARGS=--yes --install-docker'
  [ "$rc" -eq 0 ] || return 1
  grep -qx 'qpot setup --yes --install-docker' "$case_dir/qpot.log"
}

hand_off_passes_setup_status() {
  run_install good 'QPOT_SETUP_ARGS=--yes' FAKE_SETUP_RC=15
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

check 'an unsupported OS is QP-HOST-001 (exit 11)' unsupported_os
check 'an unsupported processor is QP-HOST-002 (exit 11)' unsupported_arch
check 'a good release installs after its checksum matches' good_release
check 'a good release installs the arm64 archive on arm64' good_release_arm64
check 'a redirect within the release origin is followed' same_origin_redirect
check 'a tampered archive is QP-NET-009 and installs nothing' tampered_archive
check 'tampered checksums are QP-NET-009 and install nothing' tampered_sums
check 'a malformed SHA256SUMS is QP-NET-010 and installs nothing' malformed_sums
check 'a SHA256SUMS over 64 KiB is QP-NET-010' big_sums
check 'no entry for the archive is QP-NET-010' no_entry
check 'a truncated download is QP-NET-007 and installs nothing' truncated
check 'a download cut short without a length is QP-NET-009' short_body
check 'a redirect to another origin is QP-NET-011, never contacted' other_origin_redirect
check 'a .curlrc in the home folder cannot make curl follow redirects' curlrc_ignored
check 'a redirect to another host name is QP-NET-011, never contacted' other_host_redirect
check 'a redirect loop stops' redirect_loop
check 'a plain-http download base is QP-INPUT-012 (exit 10)' http_base_refused
check 'no curl is QP-HOST-011' no_curl
check 'no checksum program is QP-HOST-010' no_checksum_tool
if command -v shasum >/dev/null; then
  check 'shasum works when sha256sum is missing' shasum_only
fi
check 'gh verifies the provenance with the pinned workflow and tag' provenance_verified
check 'provenance gh rejects is QP-NET-012 and installs nothing' provenance_rejected
check 'a missing provenance file is QP-NET-012 when gh is installed' provenance_missing
check 'QPOT_REQUIRE_PROVENANCE=1 without gh is QP-NET-012' provenance_required
check 'a gh without --source-ref is not used' old_gh_not_used
check 'QPOT_REQUIRE_PROVENANCE=1 with a too old gh is QP-NET-012' old_gh_required
check 'no release and no pinned commit is QP-NET-013' no_release_no_pin
check 'no release: the installer fetches the commit it pins' source_default_is_pin
check 'no release: the pinned commit is built from source' source_build
check 'a pinned commit that is not there is QP-NET-007' source_commit_unknown
check 'another commit than the pinned one is QP-NET-014' source_commit_mismatch
check 'no release and no Go is QP-HOST-006 (exit 11)' source_no_go
check 'an old Go is QP-HOST-006' old_go
check 'a failed build is QP-HOST-008' build_fails
check 'a binary that does not run is QP-HOST-007' broken_binary
check 'an unwritable install folder is QP-PERM-007 (exit 12)' unwritable_install_dir
check 'a good install with QPOT_NO_SETUP=1 only installs' good_install_no_setup
check 'without a terminal it says what to run next' no_terminal_says_what_next
check 'QPOT_SETUP_ARGS hands over to qpot setup' hand_off_with_args
check 'the hand-over passes on qpot setup exit status' hand_off_passes_setup_status
printf '%d/%d install script checks passed\n' "$((checks - failures))" "$checks"
[ "$failures" -eq 0 ]
