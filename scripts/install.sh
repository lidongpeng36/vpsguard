#!/bin/bash
set -euo pipefail

BINARY_NAME="vpsguard"
CONFIG_DIR="/etc/vpsguard"
DATA_DIR="/var/lib/vpsguard"
LOG_DIR="/var/log/vpsguard"
SERVICE_FILE="/etc/systemd/system/vpsguard.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Check nftables
if ! command -v nft &>/dev/null; then
    error "nft not found. Install nftables first:"
    echo "  apt install nftables   # Debian/Ubuntu"
    echo "  yum install nftables   # CentOS/RHEL"
    exit 1
fi

# Check Go (for building)
if ! command -v go &>/dev/null; then
    error "Go not found. Install Go 1.22+ first:"
    echo "  https://go.dev/dl/"
    exit 1
fi

info "Building vpsguard..."
cd "$(dirname "$0")/.."
make build

info "Installing binary..."
install -m 755 bin/$BINARY_NAME /usr/local/bin/$BINARY_NAME

info "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR/geoip"
mkdir -p "$LOG_DIR"

if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    info "Installing example config..."
    install -m 600 configs/config.example.yaml "$CONFIG_DIR/config.yaml"
    warn "Edit $CONFIG_DIR/config.yaml with your MaxMind license key!"
else
    info "Config file exists, not overwriting: $CONFIG_DIR/config.yaml"
fi

info "Installing systemd service..."
install -m 644 init/vpsguard.service "$SERVICE_FILE"
systemctl daemon-reload

info ""
info "========================================="
info " VPSGuard installed successfully!"
info "========================================="
info ""
info " Next steps:"
info "  1. Edit config:    nano $CONFIG_DIR/config.yaml"
info "  2. Set license key: Get one at https://www.maxmind.com/en/geolite2/signup"
info "  3. Validate config: vpsguard -check -config $CONFIG_DIR/config.yaml"
info "  4. Start service:   systemctl enable --now vpsguard"
info "  5. Check status:    systemctl status vpsguard"
info "  6. View logs:       journalctl -u vpsguard -f"
info ""
info " Management:"
info "  Reload config:     systemctl reload vpsguard"
info "  Force update:      kill -USR1 \$(pidof vpsguard)"
info "  Dry run:           vpsguard -dry-run -config $CONFIG_DIR/config.yaml"
info ""
