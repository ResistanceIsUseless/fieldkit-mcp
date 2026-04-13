# fieldkit-mcp — Offensive Security Reconnaissance MCP Server

A comprehensive MCP server exposing multi-engine search dorking, Shodan, GitHub OSINT, secret scanning, and ten recon CLI tools for LLM-driven security assessments.

**AUTHORIZATION NOTICE:** This server is designed for authorized security testing only. All reconnaissance activities are performed against systems where explicit written authorization has been obtained.

## Tools Exposed

| MCP Tool | Wraps | Type | Description |
|---|---|---|---|
| `dork_search` | DuckDuckGo, Google | Passive | Executes search dork queries (DDG default, supports both engines) |
| `search_github_secrets` | GitHub API | Passive | Search GitHub for exposed secrets, credentials, and API keys |
| `hunt_secrets` | `trufflehog` | Passive | Deep secret scanning with 700+ detectors, entropy analysis, verification |
| `query_wayback` | Wayback Machine | Passive | Historical URL snapshots from Archive.org |
| `lookup_shodan_host` | Shodan API | Passive | Lookup host information on Shodan |
| `search_shodan` | Shodan API | Passive | Search Shodan for hosts matching criteria |
| `resolve_shodan_dns` | Shodan API | Passive | DNS resolution via Shodan |
| `discover_subdomains` | `subfinder` | Passive | Subdomain enumeration via passive sources |
| `recon_subscope` | `subscope` | Passive/Active | Advanced subdomain enumeration pipeline (subfinder + httpx + shuffledns + alterx) |
| `scan_vulnerabilities` | `nuclei` | **Active** | Vulnerability scanning with templates |
| `enumerate_dns` | `dnsx` | Passive | DNS resolution & enumeration (supports wordlists) |
| `probe_http` | `httpx` | Passive | HTTP probing, tech detection, title extraction |
| `web_search` | DuckDuckGo HTML | Passive | Web search returning ranked URLs and snippets |
| `web_fetch` | Python `httpx` | Passive | Raw HTTP fetch with method/header/body control, ignores robots.txt |
| `web_render` | Playwright Chromium | **Active** | Render JavaScript-heavy pages with optional action sequences |
| `web_crawl` | `katana` | **Active** | Web crawling / endpoint discovery |
| `web_screenshot` | Playwright Chromium | **Active** | Capture rendered page screenshots to PNG |
| `web_extract` | selectolax + readability-lxml | Passive | Extract readable content, CSS, or XPath selections |
| `fingerprint_tech` | Wappalyzer + heuristics | Passive | Detect web technologies from headers and rendered content |
| `query_cache` | sqlite | Local | List and retrieve cached web responses |
| `recon_webscope` | `webscope` | **Active** | Web content discovery, JS analysis, secret detection, path bruteforcing |
| `recon_nmap` | `nmap` | **Active** | Network & port scanning with service/OS/vuln detection |
| `harvest_osint` | `theHarvester` | Passive | Email, subdomain & IP OSINT |
| `check_tool_status` | — | Local | Checks which binaries, integrations, and API keys are available |

Legacy `recon_*` names are still available as deprecated aliases for compatibility.

## Prerequisites

### 1. Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Recon Binaries (must be on PATH)

**ProjectDiscovery tools** (Go-based — install via `go install` or download binaries):
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

**TruffleHog** (Go-based secret scanner):
```bash
go install github.com/trufflesecurity/trufflehog/v3@latest
```

**Custom recon tools** (Go-based):
```bash
go install github.com/ResistanceIsUseless/webscope@latest
go install github.com/ResistanceIsUseless/subscope@latest
```

**Nmap** (system package):
```bash
# macOS
brew install nmap

# Debian/Ubuntu
apt-get install -y nmap
```

**theHarvester** (Python-based):
```bash
pip install theHarvester
```

### 3. Wordlists for DNS Bruteforcing (Optional)

**Recommended: SecLists**
```bash
# Install to default location
mkdir -p ~/.recon-wordlists
cd ~/.recon-wordlists
git clone https://github.com/danielmiessler/SecLists.git

# Or set custom location
export WORDLIST_DIR="/path/to/your/wordlists"
```

**Built-in wordlist aliases** (available after installing SecLists):
- `dns_subdomains_top1000` - Top 5,000 subdomains
- `dns_subdomains_top20k` - Top 20,000 subdomains
- `dns_subdomains_top110k` - Top 110,000 subdomains
- `dns_fierce` - Fierce hostlist
- `dns_bitquark` - Bitquark top 100k subdomains

**Usage:**
```
> "Use dnsx to bruteforce subdomains on example.com with dns_subdomains_top1000"
> "Run dnsx with custom wordlist at /path/to/custom.txt"
```

### 4. API Keys (env vars)

**Required for specific tools:**
```bash
export SHODAN_API_KEY="..."   # Required for Shodan tools - https://account.shodan.io/
export GITHUB_TOKEN="..."     # Required for GitHub search - https://github.com/settings/tokens
```

**Optional - enhance passive source coverage:**
```bash
export VIRUSTOTAL_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
export CHAOS_API_KEY="..."       # ProjectDiscovery Chaos
```

## Running the Server

### One-Command Docker (Recommended)

```bash
cp .env.example .env
docker compose up -d
```

Server endpoint: `http://localhost:8000/mcp`

### Native Install Helper

```bash
chmod +x install.sh
./install.sh
python fieldkit_mcp_server.py
```

### Standalone HTTP Mode

```bash
# Default port 8000
python fieldkit_mcp_server.py

# Custom port
python fieldkit_mcp_server.py --port 9000

# Or via env var
FIELDKIT_MCP_PORT=9000 python fieldkit_mcp_server.py
```

### Managed by Claude Desktop

When configured properly in `claude_desktop_config.json`, Claude Desktop will start and manage the server automatically. No manual startup needed.

## Client Configuration

### Claude Desktop (`claude_desktop_config.json`)

Claude Desktop requires a command-based configuration:

```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "command": "python",
      "args": ["/path/to/your/project/fieldkit_mcp_server.py"],
      "env": {
        "FIELDKIT_MCP_PORT": "8000"
      }
    }
  }
}
```

**Note**: Update the path to match your actual project location. The server will be managed directly by Claude Desktop.

### Alternative: Using SSE Proxy

If you prefer to run the server as a separate HTTP process, you can use the fetch proxy:

```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-fetch", "http://localhost:8000/mcp"]
    }
  }
}
```

### Claude Code (`.mcp.json` in project root)

Claude Code supports both URL and command formats:

```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Or command-based:

```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "command": "python",
      "args": ["./fieldkit_mcp_server.py"]
    }
  }
}
```

### Cursor / Other MCP Clients

Point to the streamable HTTP endpoint: `http://localhost:8000/mcp`

## Usage Examples

Once connected, the LLM can call tools like:

**Search Engine Dorking:**
> "Search for exposed config files on example.com" (uses DuckDuckGo by default)

> "Search for site:example.com filetype:sql using Google"

> "Search for login pages on example.com using both Google and DuckDuckGo"

**Secret Hunting:**
> "Search GitHub for exposed API keys related to example.com" (quick search)

> "Run TruffleHog on org:example to find all secrets with verification"

> "Scan https://github.com/company/repo with TruffleHog and verify secrets"

> "Deep scan the repo at /path/to/cloned-repo for secrets using TruffleHog"

**Historical Data:**
> "Show me Wayback Machine snapshots of example.com from 2020"

> "Find archived versions of example.com/admin"

> "Get historical snapshots of example.com/api that returned 200 status"

**Shodan:**
> "Look up 8.8.8.8 on Shodan and show me the open ports and services"

> "Search Shodan for apache servers in the US"

> "Resolve example.com using Shodan DNS"

**Subdomain Enumeration & Probing:**
> "Run subfinder against example.com and then resolve the discovered subdomains with dnsx"

> "Run subscope on example.com for full subdomain enumeration with HTTP analysis"

> "Run subfinder on example.com, then pipe results to httpx to find live web servers"

> "Probe https://example.com with httpx and show technologies"

> "Use dnsx to bruteforce subdomains on example.com with dns_subdomains_top1000 wordlist"

**Vulnerability Scanning:**
> "Use nuclei to check example.com for critical and high severity vulnerabilities"

**Web Content Discovery:**
> "Run webscope against https://example.com in in-depth mode to find hidden endpoints and secrets"

> "Use webscope with intense flow on https://example.com and focus on JavaScript analysis"

**Web Crawling:**
> "Crawl https://example.com with katana depth 3 and look for API endpoints"

**Web Surface:**
> "Use web_search for exposed staging login pages for example.com"

> "Use web_fetch on https://example.com/.well-known/security.txt with method GET"

> "Use web_render on https://example.com and click the '#login' button"

> "Take a full-page web_screenshot of https://example.com"

> "Use web_extract readability mode on https://example.com/blog/post"

> "Run fingerprint_tech for https://example.com"

> "Use query_cache to list recent cached pages"

**Network Scanning:**
> "Run a quick nmap scan on example.com to see open ports and services"

> "Use nmap vuln scan on 192.168.1.0/24 to check for vulnerabilities"

**Status Check:**
> "Check check_tool_status to see which tools are installed"

## Security Notice

⚠️ **Authorization Required**: Tools marked **Active** (nuclei, katana, webscope, subscope, nmap) send requests to targets. Only use against systems you have explicit written authorization to test. Unauthorized scanning may violate laws including the CFAA.

Some nmap scan types (SYN stealth, OS detection, UDP) require root/sudo privileges.
