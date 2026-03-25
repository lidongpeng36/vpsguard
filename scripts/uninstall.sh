#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root" >&2
    exit 1
fi

info "Stopping vpsguard service..."
systemctl stop vpsguard 2>/dev/null || true
systemctl disable vpsguard 2>/dev/null || true

info "Cleaning up nftables rules..."
nft delete table inet vpsguard 2>/dev/null || true

info "Removing binary..."
rm -f /usr/local/bin/vpsguard

info "Removing systemd service..."
rm -f /etc/systemd/system/vpsguard.service
systemctl daemon-reload

info ""
info "VPSGuard uninstalled."
warn "Config preserved at: /etc/vpsguard/"
warn "Data preserved at:   /var/lib/vpsguard/"
info "To remove all data:  rm -rf /etc/vpsguard /var/lib/vpsguard /var/log/vpsguard"
