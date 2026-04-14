#!/usr/bin/env bash
set -euo pipefail

if [ "${1:-}" = "--help" ]; then
  echo "Usage: ./install.sh"
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORDLIST_BASE="${WORDLIST_DIR:-$HOME/.recon-wordlists}"
SECLISTS_DIR="${WORDLIST_BASE}/SecLists"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[!] Missing required command: $1"
    return 1
  fi
}

echo "[*] FieldKit-MCP installer"
require_cmd python3
require_cmd pipx
require_cmd go
require_cmd git
require_cmd brew

PIPX_HOME_DIR="${PIPX_HOME:-$HOME/.local/pipx}"
MCP_VENV_PYTHON="${PIPX_HOME_DIR}/venvs/mcp/bin/python"

echo "[*] Installing Python dependencies with pipx"
pipx install --force --python python3 "mcp[cli]"
pipx runpip mcp install -r "${ROOT_DIR}/requirements.txt"
pipx runpip mcp install theHarvester

echo "[*] Installing Playwright Chromium"
"${MCP_VENV_PYTHON}" -m playwright install chromium

echo "[*] Installing Go recon tools"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ResistanceIsUseless/ipintel/cmd/ipintel@latest
go install -v github.com/resistanceisuseless/webscope@latest
go install -v github.com/resistanceisuseless/subscope/cmd/subscope@latest

echo "[*] Installing trufflehog via Homebrew"
brew install trufflehog

mkdir -p "${WORDLIST_BASE}"
if [ ! -d "${SECLISTS_DIR}" ]; then
  echo "[*] Cloning SecLists into ${SECLISTS_DIR}"
  git clone https://github.com/danielmiessler/SecLists.git "${SECLISTS_DIR}"
else
  echo "[*] SecLists already present at ${SECLISTS_DIR}"
fi

mkdir -p "${ROOT_DIR}/cache" "${ROOT_DIR}/output"

echo
echo "[+] Install complete"
echo "    - Python deps installed"
echo "    - Go tools installed to your GOPATH/bin"
echo "    - Playwright Chromium installed"
echo "    - SecLists available at ${SECLISTS_DIR}"
echo
echo "Run server: FIELDKIT_MCP_PORT=8000 ${MCP_VENV_PYTHON} ${ROOT_DIR}/fieldkit_mcp_server.py"
