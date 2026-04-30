#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  XSSSlayer — Smart Setup Script
#  Developed by alisalive.exe | github: alisalive
#  Works on: Kali Linux, Ubuntu 22.04+, Debian 12+
# ─────────────────────────────────────────────────────────────

set -euo pipefail

CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
RESET='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║         XSSSlayer — Smart Setup Script           ║"
    echo "  ║   Developed by alisalive.exe | github: alisalive ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERR]${RESET}   $*"; exit 1; }

banner

# ── 1. Refresh package list ───────────────────────────────────
info "Updating package list ..."
sudo apt-get update -qq

# ── 2. Smart Dependency Check & Install ──────────────────────
# Resolves renamed/split packages across Kali, Ubuntu, Debian versions.
# For each optional package pair, the newer name is preferred.

pkg_available() { apt-cache show "$1" > /dev/null 2>&1; }

install_pkg() {
    local pkg="$1"
    if pkg_available "$pkg"; then
        sudo apt-get install -y -qq "$pkg" && success "  $pkg" || warn "  $pkg — install failed, skipping"
    else
        warn "  $pkg — not found in repos, skipping"
    fi
}

# Resolve versioned package aliases
resolve_pkg() {
    local preferred="$1"
    local fallback="$2"
    if pkg_available "$preferred"; then
        echo "$preferred"
    elif pkg_available "$fallback"; then
        echo "$fallback"
    else
        echo ""
    fi
}

info "Installing core tools ..."
for pkg in python3 python3-pip python3-venv curl wget git; do
    install_pkg "$pkg"
done

info "Installing Playwright system dependencies (smart resolve) ..."

# Fixed packages — stable across all distros
# Fixed packages — stable across all distros
FIXED_PKGS=(
    libnss3
    libatk1.0-0t64
    libatk-bridge2.0-0t64
    libcups2t64
    libdrm2
    libxkbcommon0
    libxcomposite1
    libxdamage1
    libxfixes3
    libxrandr2
    libgbm1
    libpango-1.0-0
    libcairo2
    libnspr4
    libxss1
    libxtst6
    fonts-liberation
    xdg-utils
)

for pkg in "${FIXED_PKGS[@]}"; do
    install_pkg "$pkg"
done

# ── libasound2: renamed to libasound2t64 in Ubuntu 24.04 / Kali 2024+ ──
LIBASOUND=$(resolve_pkg "libasound2t64" "libasound2")
if [ -n "$LIBASOUND" ]; then
    install_pkg "$LIBASOUND"
else
    warn "libasound2 / libasound2t64 — not found, Playwright will install via install-deps"
fi

# ── libappindicator3-1: dropped in some distros ──
LIBAPPIND=$(resolve_pkg "libappindicator3-1" "libayatana-appindicator3-1")
if [ -n "$LIBAPPIND" ]; then
    install_pkg "$LIBAPPIND"
else
    warn "libappindicator3-1 — not found, skipping (non-critical)"
fi

success "System dependencies resolved."

# ── 3. Python virtual environment ────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    info "Creating Python virtual environment at ./venv ..."
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
success "Virtual environment activated."

# ── 4. Python packages ────────────────────────────────────────
info "Upgrading pip ..."
pip install --upgrade pip -q

info "Installing Python requirements ..."
pip install -r "$SCRIPT_DIR/requirements.txt" -q
success "Python packages installed."

# ── 5. Playwright Chromium ───────────────────────────────────
info "Installing Playwright Chromium browser ..."
python -m playwright install chromium

# Fallback: if system deps are missing, playwright install-deps covers them
info "Running playwright install-deps as safety net ..."
python -m playwright install-deps chromium 2>/dev/null || warn "install-deps skipped (may need sudo — run: sudo python -m playwright install-deps chromium)"

success "Playwright Chromium installed."

# ── 6. Verify payloads.txt ────────────────────────────────────
PAYLOAD_FILE="$SCRIPT_DIR/payloads.txt"
if [ -f "$PAYLOAD_FILE" ]; then
    COUNT=$(wc -l < "$PAYLOAD_FILE")
    success "payloads.txt found — ${COUNT} payloads loaded."
else
    warn "payloads.txt NOT found. Place it next to xss_slayer.py before running."
fi

# ── 7. Done ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║  Setup complete! Run the tool with:                      ║${RESET}"
echo -e "${GREEN}║                                                          ║${RESET}"
echo -e "${GREEN}║  source venv/bin/activate                                ║${RESET}"
echo -e "${GREEN}║  python xss_slayer.py -u \"http://TARGET/?q=x\" -p q       ║${RESET}"
echo -e "${GREEN}║                                                          ║${RESET}"
echo -e "${GREEN}║  Full god mode:                                          ║${RESET}"
echo -e "${GREEN}║  python xss_slayer.py -u \"http://TARGET\" --show-browser  ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
