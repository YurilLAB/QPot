#!/usr/bin/env bash
# QPot Installer for Linux and macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.sh | bash
#
# Installs the qpot program, then hands over to `qpot setup`, which checks the
# computer, installs Docker when you agree, and starts your first honeypot.
#
# What it installs is checked before anything is put in place:
#   - the release's SHA256SUMS list is downloaded, and the archive for this
#     computer must match its entry there (a mismatch, a missing entry or a
#     malformed list stops the install);
#   - downloads come only from GitHub's release servers: a redirect anywhere
#     else stops the install;
#   - when the GitHub CLI (gh) is installed, the archive's build provenance is
#     verified as well: it must have been built by QPot's release workflow
#     from the tag of this version (QPOT_REQUIRE_PROVENANCE=1 makes this
#     check mandatory);
#   - without a published release (no SHA256SUMS) it builds from source, but
#     only the commit pinned below, which git checks by its hash.
#
# Environment:
#   QPOT_NO_SETUP=1        install the program only; do not offer `qpot setup`
#   QPOT_SETUP_ARGS="..."  run `qpot setup` with these arguments right away,
#                          without asking (for scripts), e.g.
#                          QPOT_SETUP_ARGS="--yes --install-docker --docker-group"
#   QPOT_REQUIRE_PROVENANCE=1  stop unless gh verified the build provenance
#   QPOT_DOWNLOAD_BASE=URL the releases' download address (a mirror; must be
#                          https://, plain http only to this computer)
#
# Every failure prints an error code (QP-...) explained in doc/setup-errors.md
# and exits with that code's category status, the same as `qpot setup`.

# -E: the ERR trap also fires inside functions, so nothing fails silently.
set -Eeuo pipefail

QPOT_VERSION="1.0.1"
QPOT_REPO="https://github.com/YurilLAB/QPot"
QPOT_GH_REPO="YurilLAB/QPot"
# The one commit the installer builds when no release is published: a main
# commit that passed CI until the first release, then the tag's commit (see
# "Releases" in README.md). git checks the checkout is exactly this commit;
# a test checks both installers pin the same commit from main's history.
QPOT_SOURCE_COMMIT_PINNED="391d983c25caf611eea9d36e3942191f3bd65699"
INSTALL_DIR="${HOME}/.local/bin"
DOWNLOAD_BASE="${QPOT_DOWNLOAD_BASE:-${QPOT_REPO}/releases/download}"
SOURCE_REPO="${QPOT_SOURCE_REPO:-${QPOT_REPO}.git}"
SOURCE_COMMIT="${QPOT_SOURCE_COMMIT:-${QPOT_SOURCE_COMMIT_PINNED}}"
# Minimum Go (major.minor) required to build from source. go.mod pins a newer
# `go` directive, but Go >= 1.21 with the default GOTOOLCHAIN=auto transparently
# downloads the exact toolchain go.mod asks for, so 1.21 is the real floor (it
# is the first release that understands the toolchain directive). Older Go just
# errors confusingly, which is what this check turns into a clear message.
GO_MIN_VERSION="1.21"

# Temp dir used by the download/build path; cleaned up by the EXIT trap so a
# failure midway through does not leave a stray directory behind.
TEMP_DIR=""
cleanup() { if [ -n "${TEMP_DIR}" ]; then rm -rf "${TEMP_DIR}" 2>/dev/null || true; fi; }

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# exit_status_for prints the exit status of an error code's category. It is
# the same table as `qpot setup` uses (internal/hostsetup/errors.go); a Go
# test checks they agree.
exit_status_for() {
    case "$1" in
        INPUT) echo 10 ;;
        HOST) echo 11 ;;
        PERM) echo 12 ;;
        NET) echo 13 ;;
        BUG) echo 70 ;;
        *) echo 70 ;;
    esac
}

# die CODE WHAT WHY FIX: print a coded error in plain words and exit with
# the code's category status.
die() {
    local code=$1 what=$2 why=$3 fix=$4 cat
    trap - ERR
    cat=${code#QP-}
    cat=${cat%%-*}
    echo "" >&2
    echo -e "${RED}ERROR ${code}:${NC} ${what}" >&2
    echo "  Why:  ${why}" >&2
    echo "  Fix:  ${fix}" >&2
    echo "  More: ${QPOT_REPO}/blob/main/doc/setup-errors.md" >&2
    exit "$(exit_status_for "$cat")"
}

on_error() {
    local rc=$?
    die "QP-BUG-002" "The installer stopped unexpectedly (exit ${rc})." \
        "A command in the install script failed in a way it does not explain; see the messages above." \
        "Run the installer again. If it happens again, report it at ${QPOT_REPO}/issues"
}

detect_os() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$os" in
        linux|darwin) ;;
        *) die "QP-HOST-001" "This operating system (${os}) is not supported." \
            "QPot runs on Linux and macOS (and Windows with install.ps1)." \
            "Run QPot on a Linux server or virtual machine." ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch="amd64" ;;
        aarch64|arm64)  arch="arm64" ;;
        *) die "QP-HOST-002" "This processor type (${arch}) is not supported." \
            "QPot's container images are published for 64-bit x86 (amd64) and 64-bit ARM (arm64)." \
            "Use a 64-bit x86 or ARM machine or virtual machine." ;;
    esac

    echo "${os}_${arch}"
}

# check_prerequisites only reports: `qpot setup` installs or starts Docker
# itself (with your agreement), so a missing Docker no longer stops the
# installer.
check_prerequisites() {
    log_info "Checking prerequisites..."
    if ! command -v docker &> /dev/null; then
        log_warn "Docker is not installed yet. 'qpot setup' will show how it installs it and ask you first."
        return
    fi
    if ! docker compose version &> /dev/null; then
        log_warn "The Docker Compose plugin is missing. 'qpot setup' can install it."
    fi
    if ! docker info &> /dev/null; then
        log_warn "Docker is installed but not running, or your user may not use it yet. 'qpot setup' will help."
        return
    fi
    log_success "Docker found and running"
}

# url_origin URL prints the URL's origin (scheme://host[:port], lower case).
# Only http and https URLs without user names are accepted.
url_origin() {
    local LC_ALL=C re='^([Hh][Tt][Tt][Pp][Ss]?://[][A-Za-z0-9.:-]+)(/|$)'
    if [[ $1 =~ $re ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]'
        return 0
    fi
    return 1
}

# The origins downloads may come from: the download base, and for GitHub its
# two release-asset servers (github.com answers a release download with a
# redirect to one of them).
ALLOWED_ORIGINS=""
CURL_PROTO="=https"
check_download_base() {
    local origin
    if ! origin=$(url_origin "$DOWNLOAD_BASE"); then
        die "QP-INPUT-012" "QPOT_DOWNLOAD_BASE (${DOWNLOAD_BASE}) is not a usable web address." \
            "It must be an https:// address such as ${QPOT_REPO}/releases/download" \
            "Unset QPOT_DOWNLOAD_BASE, or set it to the https:// address of a mirror of QPot's releases."
    fi
    case "$origin" in
        https://*) ;;
        http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*|http://\[::1\]|http://\[::1\]:*)
            # Plain http only to this computer (a local mirror or the tests).
            CURL_PROTO="=http,https" ;;
        *) die "QP-INPUT-012" "QPOT_DOWNLOAD_BASE (${DOWNLOAD_BASE}) is not an https:// address." \
            "Downloads over plain http can be changed by anyone on the network." \
            "Unset QPOT_DOWNLOAD_BASE, or use the https:// address of the mirror." ;;
    esac
    ALLOWED_ORIGINS=" ${origin} "
    if [ "$origin" = "https://github.com" ]; then
        ALLOWED_ORIGINS="${ALLOWED_ORIGINS}https://objects.githubusercontent.com https://release-assets.githubusercontent.com "
    fi
}

# fetch URL DEST downloads URL to DEST with curl, following redirects one at a
# time and only to allowed origins. It returns 0 when downloaded, 10 when the
# server has no such file, 11 when a redirect pointed elsewhere, and 12 for
# any other failure; FETCH_DETAIL says what happened.
FETCH_DETAIL=""
fetch() {
    local url=$1 dest=$2 hops=0 origin out code location rc
    FETCH_DETAIL=""
    while :; do
        if ! origin=$(url_origin "$url") || [[ $ALLOWED_ORIGINS != *" ${origin} "* ]]; then
            FETCH_DETAIL="redirected to ${url%%\?*}"
            rm -f "$dest"
            return 11
        fi
        rc=0
        # -q first: ignore ~/.curlrc, which could add -L or -k.
        out=$(curl -q -sS --proto "$CURL_PROTO" --connect-timeout 20 --max-time 300 \
            -o "$dest" -w '%{http_code} %{redirect_url}' "$url" 2>"${dest}.err") || rc=$?
        if [ "$rc" -ne 0 ]; then
            FETCH_DETAIL="curl exit status ${rc}: $(tail -n 1 "${dest}.err" 2>/dev/null)"
            rm -f "$dest" "${dest}.err"
            return 12
        fi
        rm -f "${dest}.err"
        code=${out%% *}
        location=${out#* }
        case "$code" in
            200) return 0 ;;
            301|302|303|307|308)
                hops=$((hops + 1))
                if [ "$hops" -gt 5 ] || [ -z "$location" ] || [ "$location" = "$code" ]; then
                    FETCH_DETAIL="too many redirects"
                    rm -f "$dest"
                    return 12
                fi
                url=$location ;;
            404|410) rm -f "$dest"; return 10 ;;
            *) FETCH_DETAIL="the server answered HTTP ${code}"; rm -f "$dest"; return 12 ;;
        esac
    done
}

# file_sha256 FILE prints the file's SHA-256 in lower-case hex.
file_sha256() {
    local sum
    if command -v sha256sum >/dev/null 2>&1; then
        sum=$(sha256sum < "$1")
    elif command -v shasum >/dev/null 2>&1; then
        sum=$(shasum -a 256 < "$1")
    else
        sum=$(openssl dgst -sha256 -r < "$1")
    fi
    sum=${sum%% *}
    printf '%s\n' "$sum" | tr '[:upper:]' '[:lower:]'
}

have_sha256_tool() {
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1
}

# sums_lookup FILE NAME prints the checksum the SHA256SUMS list FILE gives for
# NAME. It returns 1 when the list breaks the format (then nothing in it is
# trusted) and 2 when it has no entry for NAME. The rules are the same as
# internal/release.ParseSums; a Go test runs both on the same inputs.
sums_lookup() {
    local LC_ALL=C file=$1 want=$2 size line n=0 hash="" name seen=" " found=""
    local re='^([0123456789abcdef]{64})(  | \*)([A-Za-z0-9][A-Za-z0-9._+-]*)$'
    size=$(wc -c < "$file" | tr -d ' \t')
    [ "$size" -le 65536 ] || return 1
    # bash cannot see NUL bytes, so count them by removing them.
    [ "$(tr -d '\000' < "$file" | wc -c | tr -d ' \t')" = "$size" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        [ "$n" -le 256 ] || return 1
        if [[ ! $line =~ $re ]]; then
            return 1
        fi
        name=${BASH_REMATCH[3]}
        [ "${#name}" -le 128 ] || return 1
        [[ $name != *..* ]] || return 1
        [[ $seen != *" ${name} "* ]] || return 1
        seen="${seen}${name} "
        if [ "$name" = "$want" ]; then
            hash=${BASH_REMATCH[1]}
            found=1
        fi
    done < "$file"
    [ "$n" -gt 0 ] || return 1
    [ -n "$found" ] || return 2
    printf '%s\n' "$hash"
}

# verify_provenance ARCHIVE BUNDLE checks with the GitHub CLI that QPot's
# release workflow built ARCHIVE from the tag of this version. The bundle is
# the release's attestation file, so gh needs no GitHub login for it.
verify_provenance() {
    local archive=$1 bundle=$2 out
    if ! out=$(GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 gh attestation verify "$archive" \
        --bundle "$bundle" --repo "$QPOT_GH_REPO" \
        --signer-workflow "${QPOT_GH_REPO}/.github/workflows/release.yml" \
        --source-ref "refs/tags/v${QPOT_VERSION}" --deny-self-hosted-runners 2>&1); then
        printf '%s\n' "$out" | tail -n 5 >&2
        die "QP-NET-012" "The build provenance of the QPot download could not be verified." \
            "The GitHub CLI could not confirm that QPot's release workflow built this file from tag v${QPOT_VERSION}. Nothing was installed." \
            "Run the installer again. If it fails again, do not use this download; report it at ${QPOT_REPO}/issues"
    fi
}

# have_gh_attestation reports whether gh can check the provenance the way
# verify_provenance asks: an older gh without these flags cannot pin the
# workflow and the tag, so it counts as not installed.
have_gh_attestation() {
    local help
    command -v gh >/dev/null 2>&1 || return 1
    help=$(GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 gh attestation verify --help 2>&1) || return 1
    [[ $help == *--bundle* && $help == *--signer-workflow* && $help == *--source-ref* && $help == *--deny-self-hosted-runners* ]]
}

# Build QPot from source, at the pinned commit only. Used when no release is
# published for this version. Requires Go and git.
build_from_source() {
    local temp_dir=$1 src="$1/src" head file_proto=never

    if ! [[ $SOURCE_COMMIT =~ ^[0123456789abcdef]{40}$ ]]; then
        die "QP-NET-013" "QPot v${QPOT_VERSION} has no published release the installer can check." \
            "There is no SHA256SUMS for v${QPOT_VERSION} at ${DOWNLOAD_BASE}, and this installer has no pinned source commit to build instead." \
            "Install a published release from ${QPOT_REPO}/releases, or build from a checkout you have reviewed: git clone ${QPOT_REPO}.git && cd QPot && go build -o qpot ./cmd/qpot"
    fi
    if ! command -v go &> /dev/null; then
        die "QP-HOST-006" "No ready-made QPot download exists for this computer, and Go is not installed to build it." \
            "Building QPot from source needs Go ${GO_MIN_VERSION} or newer and git." \
            "Install Go from https://go.dev/dl/ (or download a release from ${QPOT_REPO}/releases), then run the installer again."
    fi
    if ! command -v git &> /dev/null; then
        die "QP-HOST-006" "git is needed to build QPot from source, but it is not installed." \
            "No ready-made QPot download exists for this computer, so the installer builds it." \
            "Install git (for example: sudo apt-get install git), then run the installer again."
    fi

    # QPot's go.mod requires Go >= ${GO_MIN_VERSION}; an older toolchain fails
    # the build with a confusing error, so check up front. Compare the
    # "goX.Y.Z" token numerically on major.minor.
    local go_ver have_mm need_mm
    go_ver=$(go version | awk '{print $3}' | sed 's/^go//')
    have_mm=$(printf '%s' "$go_ver" | awk -F. '{printf "%d%03d", $1, $2}')
    need_mm=$(printf '%s' "$GO_MIN_VERSION" | awk -F. '{printf "%d%03d", $1, $2}')
    if [ "$have_mm" -lt "$need_mm" ]; then
        die "QP-HOST-006" "Go ${go_ver} is too old to build QPot." \
            "QPot needs Go ${GO_MIN_VERSION} or newer (newer Go downloads the exact version QPot pins by itself)." \
            "Update Go from https://go.dev/dl/ or install a release from ${QPOT_REPO}/releases, then run the installer again."
    fi

    log_info "Building QPot from source, commit ${SOURCE_COMMIT} (Go $(go version | awk '{print $3}'))..."
    # Fetch exactly the pinned commit. git names every object by its hash,
    # so a checkout whose HEAD is that commit has exactly that commit's files.
    # Only https (and a local folder when QPOT_SOURCE_REPO is one) may be used.
    case "$SOURCE_REPO" in
        https://*) ;;
        /*|file://*) file_proto=always ;;
        *) die "QP-INPUT-012" "QPOT_SOURCE_REPO (${SOURCE_REPO}) is not an https:// address." \
            "The source code must come over https." "Unset QPOT_SOURCE_REPO, or set it to an https:// git address." ;;
    esac
    if ! { git init -q "$src" && git -C "$src" -c protocol.allow=never -c protocol.https.allow=always \
        -c protocol.file.allow="$file_proto" -c transfer.fsckObjects=true \
        fetch -q --depth 1 "$SOURCE_REPO" "$SOURCE_COMMIT" && git -C "$src" checkout -q --detach FETCH_HEAD; } >/dev/null 2>&1; then
        die "QP-NET-007" "The QPot source code could not be downloaded." \
            "git could not fetch commit ${SOURCE_COMMIT} from ${SOURCE_REPO} (no internet connection, GitHub is blocked, or the commit does not exist there)." \
            "Check the internet connection and run the installer again."
    fi
    head=$(git -C "$src" rev-parse HEAD)
    if [ "$head" != "$SOURCE_COMMIT" ]; then
        die "QP-NET-014" "The downloaded source code is not the commit the installer expects." \
            "git checked out ${head}, but the installer pins ${SOURCE_COMMIT}. Nothing was built." \
            "Run the installer again. If it happens again, report it at ${QPOT_REPO}/issues"
    fi
    # Dependencies are checked against go.sum (part of the pinned commit): the
    # build may not change go.mod or go.sum, and with GOSUMDB on and the
    # opt-outs cleared nothing unchecked can be fetched.
    if ! ( cd "$src" && env -u GONOSUMDB -u GONOSUMCHECK -u GONOVERIFY -u GOINSECURE -u GOPRIVATE \
        GOFLAGS=-mod=readonly GOSUMDB=sum.golang.org GOTOOLCHAIN="${GOTOOLCHAIN:-auto}" \
        go build -trimpath -o "${temp_dir}/qpot" ./cmd/qpot ); then
        die "QP-HOST-008" "Building QPot from source failed." \
            "The Go build stopped with an error (shown above); an old Go or no internet access for Go's downloads are the usual reasons." \
            "Read the build output above, update Go if it is old, and run the installer again."
    fi
    log_success "Built QPot from source"
}

# download_release PLATFORM downloads this version's archive for PLATFORM,
# checks it against SHA256SUMS (and its provenance when gh is installed) and
# leaves the qpot program in TEMP_DIR. It returns 1 when no release is
# published (no SHA256SUMS), so the caller builds from source.
download_release() {
    local platform=$1 rel archive want got rc
    rel="${DOWNLOAD_BASE}/v${QPOT_VERSION}"
    archive="qpot_${QPOT_VERSION}_${platform}.tar.gz"

    log_info "Downloading the checksum list of QPot v${QPOT_VERSION}..."
    rc=0
    fetch "${rel}/SHA256SUMS" "${TEMP_DIR}/SHA256SUMS" || rc=$?
    case "$rc" in
        0) ;;
        10) log_warn "No published release v${QPOT_VERSION} (no SHA256SUMS); building from source"
            return 1 ;;
        11) die_redirect ;;
        *) die "QP-NET-007" "The QPot checksum list could not be downloaded." \
            "${FETCH_DETAIL} (${rel}/SHA256SUMS)" \
            "Check the internet connection and run the installer again." ;;
    esac
    rc=0
    want=$(sums_lookup "${TEMP_DIR}/SHA256SUMS" "$archive") || rc=$?
    case "$rc" in
        0) ;;
        2) die "QP-NET-010" "The release's checksum list has no entry for ${archive}." \
            "Without an entry the download cannot be checked, so nothing was installed." \
            "Run the installer again later. If it keeps happening, report it at ${QPOT_REPO}/issues" ;;
        *) die "QP-NET-010" "The release's checksum list (SHA256SUMS) is not valid." \
            "It is not in the format the release writes, so none of it is trusted and nothing was installed." \
            "Run the installer again later. If it keeps happening, report it at ${QPOT_REPO}/issues" ;;
    esac

    log_info "Downloading ${archive}..."
    rc=0
    fetch "${rel}/${archive}" "${TEMP_DIR}/${archive}" || rc=$?
    case "$rc" in
        0) ;;
        10) die "QP-NET-007" "The QPot download failed." \
            "The release lists ${archive}, but the file is missing." \
            "Run the installer again later. If it keeps happening, report it at ${QPOT_REPO}/issues" ;;
        11) die_redirect ;;
        *) die "QP-NET-007" "The QPot download failed." "${FETCH_DETAIL} (${archive}). Nothing was installed." \
            "Check the internet connection and run the installer again." ;;
    esac
    got=$(file_sha256 "${TEMP_DIR}/${archive}")
    if [ "$got" != "$want" ]; then
        die "QP-NET-009" "The QPot download does not match its published checksum." \
            "${archive} has SHA-256 ${got}, but SHA256SUMS says ${want}. It was damaged or changed on the way; nothing was installed." \
            "Run the installer again. If it happens again, do not install from this network; report it at ${QPOT_REPO}/issues"
    fi
    log_success "Checksum matches SHA256SUMS (${got})"

    if have_gh_attestation; then
        local bundle="qpot_${QPOT_VERSION}_provenance.sigstore.json"
        rc=0
        fetch "${rel}/${bundle}" "${TEMP_DIR}/${bundle}" || rc=$?
        case "$rc" in
            0) ;;
            11) die_redirect ;;
            *) die "QP-NET-012" "The build provenance of the QPot download could not be verified." \
                "The release's provenance file (${bundle}) could not be downloaded: ${FETCH_DETAIL:-it is missing}. Nothing was installed." \
                "Run the installer again. If it keeps happening, report it at ${QPOT_REPO}/issues" ;;
        esac
        verify_provenance "${TEMP_DIR}/${archive}" "${TEMP_DIR}/${bundle}"
        log_success "Build provenance verified: built by ${QPOT_GH_REPO}'s release workflow from tag v${QPOT_VERSION}"
    elif [ "${QPOT_REQUIRE_PROVENANCE:-}" = "1" ]; then
        die "QP-NET-012" "The build provenance of the QPot download could not be verified." \
            "QPOT_REQUIRE_PROVENANCE=1 is set, but the GitHub CLI (gh) is not installed, or is too old to check the workflow and the tag (its gh attestation verify has no --source-ref). Nothing was installed." \
            "Install or update the GitHub CLI (https://cli.github.com), or unset QPOT_REQUIRE_PROVENANCE, then run the installer again."
    else
        log_info "Build provenance not checked (the GitHub CLI 'gh' is not installed, or is too old). To check it yourself:"
        log_info "  gh attestation verify ${archive} --repo ${QPOT_GH_REPO}"
    fi

    # Take only the program out of the checked archive.
    mkdir "${TEMP_DIR}/x"
    if ! tar -xzf "${TEMP_DIR}/${archive}" -C "${TEMP_DIR}/x" qpot 2>/dev/null \
        || [ ! -f "${TEMP_DIR}/x/qpot" ] || [ -L "${TEMP_DIR}/x/qpot" ]; then
        die "QP-HOST-007" "The QPot download could not be unpacked." \
            "${archive} matched its checksum but holds no qpot program." \
            "Report it at ${QPOT_REPO}/issues"
    fi
    mv "${TEMP_DIR}/x/qpot" "${TEMP_DIR}/qpot"
    log_success "Downloaded and checked QPot v${QPOT_VERSION}"
}

die_redirect() {
    die "QP-NET-011" "A download was redirected to a server QPot does not publish from." \
        "${FETCH_DETAIL}. QPot releases come only from ${DOWNLOAD_BASE} and GitHub's download servers, so the installer stopped. Nothing was installed." \
        "Check for a proxy or a captive portal on this network, then run the installer again from a trusted network."
}

download_qpot() {
    local platform=$1
    TEMP_DIR=$(mktemp -d)

    check_download_base
    if ! command -v curl &> /dev/null; then
        die "QP-HOST-011" "curl is not installed." \
            "The installer downloads QPot and its checksum list with curl." \
            "Install curl (for example: sudo apt-get install curl), then run the installer again."
    fi
    if ! have_sha256_tool; then
        die "QP-HOST-010" "No program to check a download's checksum was found." \
            "The installer checks the QPot download with sha256sum, shasum or openssl, and none of them is installed." \
            "Install coreutils (sha256sum) or openssl, then run the installer again."
    fi
    if ! download_release "$platform"; then
        build_from_source "$TEMP_DIR"
    fi

    if [ ! -f "${TEMP_DIR}/qpot" ]; then
        die "QP-HOST-008" "No qpot program was produced." \
            "The download or build finished without leaving the qpot program behind." \
            "Run the installer again; if it happens again, report it at ${QPOT_REPO}/issues"
    fi

    if ! mkdir -p "$INSTALL_DIR" || ! cp "${TEMP_DIR}/qpot" "$INSTALL_DIR/" || ! chmod +x "${INSTALL_DIR}/qpot"; then
        die "QP-PERM-007" "The qpot program could not be copied to ${INSTALL_DIR}." \
            "That folder is not writable, or the disk is full." \
            "Check that you can write to ${INSTALL_DIR} (and df -h ${HOME}), then run the installer again."
    fi

    # Verify the installed binary actually runs on this machine (catches a
    # wrong-arch download or a corrupt build before we claim success).
    if ! "${INSTALL_DIR}/qpot" --version &> /dev/null; then
        die "QP-HOST-007" "The installed qpot program does not run on this computer." \
            "The download was probably for a different processor type, or it was damaged." \
            "Build it from source: git clone ${QPOT_REPO}.git && cd QPot && go build -o qpot ./cmd/qpot"
    fi

    log_success "QPot installed to ${INSTALL_DIR}/qpot"
}

add_to_path() {
    local shell_rc="" path_line=""

    # Use shell-appropriate PATH syntax. fish does NOT understand
    # `export PATH=...` - writing bash syntax into config.fish breaks the user's
    # shell on next start - so emit `fish_add_path` for it instead.
    case "${SHELL:-}" in
        */bash) shell_rc="${HOME}/.bashrc"; path_line="export PATH=\"\$PATH:${INSTALL_DIR}\"" ;;
        */zsh)  shell_rc="${HOME}/.zshrc";  path_line="export PATH=\"\$PATH:${INSTALL_DIR}\"" ;;
        */fish) shell_rc="${HOME}/.config/fish/config.fish"; path_line="fish_add_path ${INSTALL_DIR}" ;;
    esac

    if [[ -z "$shell_rc" ]]; then
        # Unknown/!$SHELL login shell (or none): the binary is installed, just
        # not auto-added to PATH. Tell the user how to reach it.
        if ! echo ":$PATH:" | grep -q ":${INSTALL_DIR}:"; then
            log_warn "${INSTALL_DIR} is not on your PATH. Add it, or run qpot as ${INSTALL_DIR}/qpot."
        fi
        return
    fi

    # The rc file's directory may not exist yet (notably ~/.config/fish); create
    # it so the append below can't fail the whole install under set -e.
    mkdir -p "$(dirname "$shell_rc")" 2>/dev/null || true

    if ! grep -q "$INSTALL_DIR" "$shell_rc" 2>/dev/null; then
        echo "$path_line" >> "$shell_rc"
        log_success "Added ${INSTALL_DIR} to PATH in ${shell_rc}"
        log_info "Restart your shell or run 'source ${shell_rc}' to update the current one"
    fi
}

print_banner() {
    cat << 'EOF'
    ____  ____   ____  _______
   / __ \/ __ \ / __ \/__  __/
  / / / / / / // / / /  / /
 / /_/ / /_/ // /_/ /  / /
/_____/\____/ \____/  /_/

EOF
}

print_success() {
    echo ""
    log_success "QPot v${QPOT_VERSION} installed successfully!"
    echo ""
    echo "Next: set up your first honeypot with"
    echo "  qpot setup"
    echo "It checks this computer, installs Docker if needed (it shows the commands"
    echo "and asks first), starts QPot and prints the web UI address and how to log in."
    echo ""
    echo "Other commands:"
    echo "  qpot doctor                # Check it end to end at any time"
    echo "  qpot status                # Check status"
    echo "  qpot honeypot list         # List available honeypots"
    echo "  qpot --help                # Show all commands"
    echo ""
}

# hand_off runs `qpot setup` straight away when that is possible: with
# QPOT_SETUP_ARGS, or after asking on the terminal (curl | bash has the
# script on stdin, so the question and setup itself use /dev/tty).
hand_off() {
    local qpot="${INSTALL_DIR}/qpot" answer=""
    if [ "${QPOT_NO_SETUP:-}" = "1" ]; then
        return
    fi
    if [ -n "${QPOT_SETUP_ARGS:-}" ]; then
        log_info "Running: qpot setup ${QPOT_SETUP_ARGS}"
        cleanup
        trap - EXIT ERR
        # Word splitting is intended: QPOT_SETUP_ARGS holds several flags.
        # shellcheck disable=SC2086
        exec "$qpot" setup ${QPOT_SETUP_ARGS}
    fi
    # Only offer it when a terminal can be opened for the questions.
    if ! { : </dev/tty; } 2>/dev/null; then
        echo "Run 'qpot setup' (or ${qpot} setup) to continue."
        return
    fi
    printf "Run 'qpot setup' now? [Y/n] " >/dev/tty
    read -r answer </dev/tty || answer="n"
    case "$answer" in
        ""|y|Y|yes|YES|Yes)
            cleanup
            trap - EXIT ERR
            exec "$qpot" setup </dev/tty
            ;;
        *) echo "OK. Run 'qpot setup' when you are ready." ;;
    esac
}

main() {
    trap cleanup EXIT
    trap on_error ERR
    print_banner

    local platform
    # detect_os reports its own error; pass its exit status on.
    platform=$(detect_os) || exit $?
    check_prerequisites
    download_qpot "$platform"
    add_to_path
    print_success
    hand_off
}

# QPOT_INSTALL_FUNCTIONS_ONLY=1 loads the functions without installing
# anything (the tests check the checksum parser this way).
if [ "${QPOT_INSTALL_FUNCTIONS_ONLY:-}" != "1" ]; then
    main "$@"
fi
