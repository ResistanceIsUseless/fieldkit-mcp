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
require_cmd pip
require_cmd go
require_cmd git

echo "[*] Installing Python dependencies"
pip install -r "${ROOT_DIR}/requirements.txt"
pip install theHarvester

echo "[*] Installing Playwright Chromium"
python3 -m playwright install chromium

echo "[*] Installing Go recon tools"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/trufflesecurity/trufflehog/v3@latest
go install -v github.com/ResistanceIsUseless/webscope@latest
go install -v github.com/ResistanceIsUseless/subscope@latest

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
echo "Run server: FIELDKIT_MCP_PORT=8000 python3 ${ROOT_DIR}/fieldkit_mcp_server.py"
