#!/usr/bin/env bash
# QPot Installer for Linux and macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.sh | bash
#
# Installs the qpot program, then hands over to `qpot setup`, which checks the
# computer, installs Docker when you agree, and starts your first honeypot.
#
# Environment:
#   QPOT_NO_SETUP=1        install the program only; do not offer `qpot setup`
#   QPOT_SETUP_ARGS="..."  run `qpot setup` with these arguments right away,
#                          without asking (for scripts), e.g.
#                          QPOT_SETUP_ARGS="--yes --install-docker --docker-group"
#
# Every failure prints an error code (QP-...) explained in doc/setup-errors.md
# and exits with that code's category status, the same as `qpot setup`.

# -E: the ERR trap also fires inside functions, so nothing fails silently.
set -Eeuo pipefail

QPOT_VERSION="0.1.0"
QPOT_REPO="https://github.com/YurilLAB/QPot"
INSTALL_DIR="${HOME}/.local/bin"
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
trap cleanup EXIT
trap on_error ERR

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

# Build QPot from source. Used as a fallback when no prebuilt release is
# available for this platform (or the download fails). Requires Go and git.
build_from_source() {
    local temp_dir=$1

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
    # Building may need to fetch the toolchain go.mod pins; make sure that path
    # is enabled rather than failing on a 'go.mod requires go >= ...' error.
    export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

    log_info "Building QPot from source (Go $(go version | awk '{print $3}'))..."
    if ! git clone --depth 1 "${QPOT_REPO}.git" "${temp_dir}/src" >/dev/null 2>&1; then
        die "QP-NET-007" "The QPot source code could not be downloaded." \
            "git could not reach ${QPOT_REPO}.git (no internet connection, or GitHub is blocked)." \
            "Check the internet connection and run the installer again."
    fi
    if ! ( cd "${temp_dir}/src" && go build -o "${temp_dir}/qpot" ./cmd/qpot ); then
        die "QP-HOST-008" "Building QPot from source failed." \
            "The Go build stopped with an error (shown above); an old Go or no internet access for Go's downloads are the usual reasons." \
            "Read the build output above, update Go if it is old, and run the installer again."
    fi
    log_success "Built QPot from source"
}

download_qpot() {
    local platform=$1
    local binary_name="qpot_${QPOT_VERSION}_${platform}"
    local download_url="${QPOT_REPO}/releases/download/v${QPOT_VERSION}/${binary_name}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    local temp_dir="$TEMP_DIR"

    log_info "Downloading QPot v${QPOT_VERSION}..."

    local downloaded=0
    if command -v curl &> /dev/null; then
        curl -fsSL --max-time 300 "$download_url" -o "${temp_dir}/qpot.tar.gz" && downloaded=1
    elif command -v wget &> /dev/null; then
        wget -q --timeout=300 "$download_url" -O "${temp_dir}/qpot.tar.gz" && downloaded=1
    fi

    if [[ "$downloaded" == "1" ]] && tar -xzf "${temp_dir}/qpot.tar.gz" -C "$temp_dir" 2>/dev/null; then
        log_success "Downloaded prebuilt binary"
    else
        log_warn "No prebuilt binary for ${platform} (v${QPOT_VERSION}); building from source"
        build_from_source "$temp_dir"
    fi

    if [ ! -f "${temp_dir}/qpot" ]; then
        die "QP-HOST-008" "No qpot program was produced." \
            "The download or build finished without leaving the qpot program behind." \
            "Run the installer again; if it happens again, report it at ${QPOT_REPO}/issues"
    fi

    if ! mkdir -p "$INSTALL_DIR" || ! cp "${temp_dir}/qpot" "$INSTALL_DIR/" || ! chmod +x "${INSTALL_DIR}/qpot"; then
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

main "$@"
