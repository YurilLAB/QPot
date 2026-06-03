#!/usr/bin/env bash
# QPot Installer for Linux and macOS
# Usage: curl -fsSL https://get.qpot.io | bash

set -euo pipefail

QPOT_VERSION="0.1.0"
QPOT_REPO="https://github.com/YurilLAB/QPot"
INSTALL_DIR="${HOME}/.local/bin"
DATA_DIR="${HOME}/.qpot"
# Minimum Go (major.minor) required to build from source. go.mod pins a newer
# `go` directive, but Go >= 1.21 with the default GOTOOLCHAIN=auto transparently
# downloads the exact toolchain go.mod asks for, so 1.21 is the real floor (it
# is the first release that understands the toolchain directive). Older Go just
# errors confusingly, which is what this check turns into a clear message.
GO_MIN_VERSION="1.21"

# Temp dir used by the download/build path; cleaned up by the EXIT trap so a
# failure midway through does not leave a stray directory behind.
TEMP_DIR=""
cleanup() { [ -n "${TEMP_DIR}" ] && rm -rf "${TEMP_DIR}" 2>/dev/null || true; }
on_error() {
    local rc=$?
    echo ""
    log_error "Installation failed (exit ${rc}). See the messages above."
    echo "  If this looks like a bug, please report it: ${QPOT_REPO}/issues"
    exit "$rc"
}
trap cleanup EXIT
trap on_error ERR

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

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_os() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        linux|darwin) ;;
        *) log_error "Unsupported OS: ${os} (QPot supports Linux and macOS)"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch="amd64" ;;
        aarch64|arm64)  arch="arm64" ;;
        *)       log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    echo "${os}_${arch}"
}

# docker_install_hint prints a distro/OS-appropriate command for installing
# Docker, so the error message is actionable instead of a bare URL.
docker_install_hint() {
    echo "  Install Docker: https://docs.docker.com/engine/install/"
    if [ "$(uname -s)" = "Darwin" ]; then
        echo "  On macOS:  brew install --cask docker   (then launch Docker Desktop)"
        return
    fi
    local id=""
    [ -r /etc/os-release ] && id=$(. /etc/os-release 2>/dev/null; echo "${ID}${ID_LIKE:+ $ID_LIKE}")
    # Order matters: RHEL-family distros (Rocky/Alma/CentOS) carry
    # ID_LIKE="...fedora", so they must be matched BEFORE the *fedora* arm or
    # they'd be told to `dnf install docker` (their distro package, often
    # podman-docker) instead of Docker CE's `docker-ce`. (*suse* already covers
    # *opensuse*, so it is not listed separately.)
    case "$id" in
        *arch*|*manjaro*)        echo "  sudo pacman -S docker docker-compose && sudo systemctl enable --now docker" ;;
        *debian*|*ubuntu*)       echo "  sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin && sudo systemctl enable --now docker" ;;
        *rhel*|*centos*|*rocky*|*almalinux*) echo "  sudo dnf install -y docker-ce docker-compose-plugin && sudo systemctl enable --now docker" ;;
        *fedora*)                echo "  sudo dnf install -y docker docker-compose-plugin && sudo systemctl enable --now docker" ;;
        *suse*)                  echo "  sudo zypper install -y docker docker-compose && sudo systemctl enable --now docker" ;;
        *)                       echo "  Use your distribution's package manager to install docker + the compose plugin." ;;
    esac
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed."
        docker_install_hint
        exit 1
    fi

    # Check Docker Compose. v2 is shipped as the `docker compose` subcommand
    # on every supported distro now, but Arch users may still have v1
    # (`docker-compose`) from an older AUR package; accept either.
    if ! docker compose version &> /dev/null && ! docker-compose --version &> /dev/null; then
        log_error "Docker Compose is not installed (need the 'docker compose' plugin or docker-compose v1)."
        docker_install_hint
        exit 1
    fi

    log_success "Docker found"

    # The CLI and binary install do not need a running daemon, but 'qpot up'
    # will. Probe the daemon now and warn early (don't fail) with the most
    # common fix, since the daemon being down / unreachable is the #1 first-run
    # problem. macOS Docker Desktop has no 'docker' unix group, so skip the
    # group check there.
    if ! docker info &> /dev/null; then
        log_warn "Docker is installed but the daemon is not reachable."
        if [ "$(uname -s)" = "Darwin" ]; then
            echo "  Start Docker Desktop, then re-run 'qpot up'."
        else
            echo "  Try: sudo systemctl start docker"
            if ! groups 2>/dev/null | grep -qw docker; then
                echo "  If you see a permission error, add yourself to the docker group:"
                echo "    sudo usermod -aG docker $USER && newgrp docker"
            fi
        fi
    fi
}

# Build QPot from source. Used as a fallback when no prebuilt release is
# available for this platform (or the download fails). Requires Go and git.
build_from_source() {
    local temp_dir=$1

    if ! command -v go &> /dev/null; then
        log_error "No prebuilt binary available and Go is not installed to build from source."
        echo "  Install Go ${GO_MIN_VERSION}+ (https://go.dev/dl/) or download a release from:"
        echo "  ${QPOT_REPO}/releases"
        exit 1
    fi
    if ! command -v git &> /dev/null; then
        log_error "git is required to build from source. Please install git."
        exit 1
    fi

    # QPot's go.mod requires Go >= ${GO_MIN_VERSION}; an older toolchain fails
    # the build with a confusing error, so check up front. Compare the
    # "goX.Y.Z" token numerically on major.minor.
    local go_ver have_mm need_mm
    go_ver=$(go version | awk '{print $3}' | sed 's/^go//')
    have_mm=$(printf '%s' "$go_ver" | awk -F. '{printf "%d%03d", $1, $2}')
    need_mm=$(printf '%s' "$GO_MIN_VERSION" | awk -F. '{printf "%d%03d", $1, $2}')
    if [ "$have_mm" -lt "$need_mm" ]; then
        log_error "Go ${go_ver} is too old; QPot needs Go ${GO_MIN_VERSION}+ (newer Go auto-downloads the exact toolchain go.mod pins). Update Go or install a prebuilt release."
        exit 1
    fi
    # Building may need to fetch the toolchain go.mod pins; make sure that path
    # is enabled rather than failing on a 'go.mod requires go >= ...' error.
    export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

    log_info "Building QPot from source (Go $(go version | awk '{print $3}'))..."
    git clone --depth 1 "${QPOT_REPO}.git" "${temp_dir}/src" >/dev/null 2>&1 || {
        log_error "Failed to clone ${QPOT_REPO}.git"
        exit 1
    }
    ( cd "${temp_dir}/src" && go build -o "${temp_dir}/qpot" ./cmd/qpot ) || {
        log_error "go build failed"
        exit 1
    }
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
        curl -fsSL "$download_url" -o "${temp_dir}/qpot.tar.gz" && downloaded=1
    elif command -v wget &> /dev/null; then
        wget -q "$download_url" -O "${temp_dir}/qpot.tar.gz" && downloaded=1
    fi

    if [[ "$downloaded" == "1" ]] && tar -xzf "${temp_dir}/qpot.tar.gz" -C "$temp_dir" 2>/dev/null; then
        log_success "Downloaded prebuilt binary"
    else
        log_warn "No prebuilt binary for ${platform} (v${QPOT_VERSION}); building from source"
        build_from_source "$temp_dir"
    fi

    if [ ! -f "${temp_dir}/qpot" ]; then
        log_error "Install artifact missing (no qpot binary was produced)."
        exit 1
    fi

    # Create install directory
    mkdir -p "$INSTALL_DIR"
    cp "${temp_dir}/qpot" "$INSTALL_DIR/"
    chmod +x "${INSTALL_DIR}/qpot"

    # Verify the installed binary actually runs on this machine (catches a
    # wrong-arch download or a corrupt build before we claim success).
    if ! "${INSTALL_DIR}/qpot" --version &> /dev/null; then
        log_error "Installed binary failed to execute (${INSTALL_DIR}/qpot --version)."
        echo "  This usually means an architecture mismatch. Try building from source:"
        echo "    git clone ${QPOT_REPO}.git && cd QPot && go build -o qpot ./cmd/qpot"
        exit 1
    fi

    log_success "QPot installed to ${INSTALL_DIR}/qpot"
}

add_to_path() {
    local shell_rc="" path_line=""

    # Use shell-appropriate PATH syntax. fish does NOT understand
    # `export PATH=...` - writing bash syntax into config.fish breaks the user's
    # shell on next start - so emit `fish_add_path` for it instead.
    case "$SHELL" in
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

create_default_instance() {
    log_info "Creating default QPot instance..."
    
    if ! "${INSTALL_DIR}/qpot" instance create default 2>/dev/null; then
        log_warn "Default instance may already exist"
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
    echo "Quick Start:"
    echo "  qpot up                    # Start default instance"
    echo "  qpot status                # Check status"
    echo "  qpot honeypot list         # List available honeypots"
    echo "  qpot --help                # Show all commands"
    echo ""
    echo "Web UI: http://localhost:8080"
    echo ""
    echo "Safety Features:"
    echo "  ✓ Sandboxed containers (gVisor/Kata when available)"
    echo "  ✓ Resource limits (CPU, memory, PIDs)"
    echo "  ✓ Read-only filesystems"
    echo "  ✓ Capability dropping"
    echo "  ✓ Network isolation"
    echo ""
}

main() {
    print_banner
    
    local platform=$(detect_os)
    check_prerequisites
    download_qpot "$platform"
    add_to_path
    create_default_instance
    print_success
}

main "$@"
