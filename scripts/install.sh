#!/usr/bin/env bash
# QPot Installer for Linux and macOS
# Usage: curl -fsSL https://get.qpot.io | bash

set -euo pipefail

QPOT_VERSION="0.1.0"
QPOT_REPO="https://github.com/qpot/qpot"
INSTALL_DIR="${HOME}/.local/bin"
DATA_DIR="${HOME}/.qpot"

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
    
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        arm64)   arch="arm64" ;;
        *)       log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac
    
    echo "${os}_${arch}"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first:"
        echo "  https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null && ! docker-compose --version &> /dev/null; then
        log_error "Docker Compose is not installed."
        exit 1
    fi
    
    log_success "Docker found"
    
    # Check if user is in docker group
    if ! groups | grep -q '\bdocker\b'; then
        log_warn "User is not in the 'docker' group. You may need to run with sudo or:"
        echo "  sudo usermod -aG docker $USER && newgrp docker"
    fi
}

download_qpot() {
    local platform=$1
    local binary_name="qpot_${QPOT_VERSION}_${platform}"
    local download_url="${QPOT_REPO}/releases/download/v${QPOT_VERSION}/${binary_name}.tar.gz"
    local temp_dir=$(mktemp -d)
    
    log_info "Downloading QPot v${QPOT_VERSION}..."
    
    if command -v curl &> /dev/null; then
        curl -fsSL "$download_url" -o "${temp_dir}/qpot.tar.gz"
    elif command -v wget &> /dev/null; then
        wget -q "$download_url" -O "${temp_dir}/qpot.tar.gz"
    else
        log_error "Neither curl nor wget is installed"
        exit 1
    fi
    
    tar -xzf "${temp_dir}/qpot.tar.gz" -C "$temp_dir"
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    cp "${temp_dir}/qpot" "$INSTALL_DIR/"
    chmod +x "${INSTALL_DIR}/qpot"
    
    rm -rf "$temp_dir"
    log_success "QPot installed to ${INSTALL_DIR}/qpot"
}

add_to_path() {
    local shell_rc=""
    
    case "$SHELL" in
        */bash) shell_rc="${HOME}/.bashrc" ;;
        */zsh)  shell_rc="${HOME}/.zshrc" ;;
        */fish) shell_rc="${HOME}/.config/fish/config.fish" ;;
    esac
    
    if [[ -n "$shell_rc" ]]; then
        if ! grep -q "$INSTALL_DIR" "$shell_rc" 2>/dev/null; then
            echo "export PATH=\"\$PATH:${INSTALL_DIR}\"" >> "$shell_rc"
            log_success "Added ${INSTALL_DIR} to PATH in ${shell_rc}"
            log_info "Run 'source ${shell_rc}' to update your current shell"
        fi
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
