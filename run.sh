#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Shadow API Scanner — Linux Build & Run Script
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
DIST_DIR="$SCRIPT_DIR/dist"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "  ____  _               _                  _    ____ ___ "
    echo " / ___|| |__   __ _  __| | _____      __  / \\  |  _ \\_ _|"
    echo " \\___ \\| '_ \\ / _\` |/ _\` |/ _ \\ \\ /\\ / / / _ \\ | |_) | | "
    echo "  ___) | | | | (_| | (_| | (_) \\ V  V / / ___ \\|  __/| | "
    echo " |____/|_| |_|\\__,_|\\__,_|\\___/ \\_/\\_/ /_/   \\_\\_|  |___|"
    echo "          Scanner v1.0.0 — Build & Run Script"
    echo -e "${NC}"
}

setup() {
    echo -e "${GREEN}[+] Setting up virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    echo -e "${GREEN}[+] Installing dependencies...${NC}"
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    pip install -r "$SCRIPT_DIR/requirements.txt" > /dev/null 2>&1

    echo -e "${GREEN}[+] Installing Playwright browsers...${NC}"
    python -m playwright install chromium 2>/dev/null || echo -e "${RED}[!] Playwright browser install failed (optional for --no-browser mode)${NC}"

    echo -e "${GREEN}[✓] Setup complete.${NC}"
}

run() {
    source "$VENV_DIR/bin/activate" 2>/dev/null || setup
    python -m shadow_api_scanner "$@"
}

build_binary() {
    echo -e "${GREEN}[+] Building standalone Linux binary...${NC}"
    source "$VENV_DIR/bin/activate" 2>/dev/null || setup
    pip install pyinstaller > /dev/null 2>&1
    pyinstaller \
        --onefile \
        --name shadow-scan \
        --hidden-import shadow_api_scanner \
        --hidden-import shadow_api_scanner.phase1 \
        --hidden-import shadow_api_scanner.phase2 \
        --hidden-import shadow_api_scanner.phase3 \
        --hidden-import shadow_api_scanner.phase4 \
        --hidden-import shadow_api_scanner.utils \
        --hidden-import shadow_api_scanner.core \
        --collect-all shadow_api_scanner \
        "$SCRIPT_DIR/shadow_api_scanner/__main__.py"

    echo -e "${GREEN}[✓] Binary built: $DIST_DIR/shadow-scan${NC}"
    echo -e "${CYAN}    Usage: ./dist/shadow-scan https://target-spa.com${NC}"
}

# ── Main ──
banner

case "${1:-run}" in
    setup)
        setup
        ;;
    build)
        build_binary
        ;;
    run)
        shift 2>/dev/null || true
        run "$@"
        ;;
    *)
        # If first arg looks like a URL, run with it
        if [[ "$1" == http* ]]; then
            run "$@"
        else
            echo "Usage: $0 {setup|build|run} [options]"
            echo ""
            echo "Commands:"
            echo "  setup   Install dependencies and Playwright"
            echo "  build   Create standalone binary with PyInstaller"
            echo "  run     Run the scanner (default)"
            echo ""
            echo "Examples:"
            echo "  $0 setup"
            echo "  $0 run https://example.com"
            echo "  $0 https://example.com --verbose --no-browser"
            echo "  $0 build"
        fi
        ;;
esac
