# recon_mcp — Offensive Security Reconnaissance MCP Server

A comprehensive MCP server exposing multi-engine search dorking (Google, DuckDuckGo), Shodan integration, and five recon CLI tools for LLM-driven security assessments.

**AUTHORIZATION NOTICE:** This server is designed for authorized security testing only. All reconnaissance activities are performed against systems where explicit written authorization has been obtained.

## Tools Exposed

| MCP Tool | Wraps | Type | Description |
|---|---|---|---|
| `recon_google_dork` | DuckDuckGo, Google | Passive | Executes search dork queries (DDG default, supports both engines) |
| `recon_github_search` | GitHub API | Passive | Quick search GitHub for exposed secrets, credentials, API keys |
| `recon_trufflehog` | `trufflehog` | Passive | Deep secret scanning with 200+ detectors, entropy analysis, verification |
| `recon_wayback` | Wayback Machine | Passive | Historical snapshots from Archive.org |
| `recon_shodan_host` | Shodan API | Passive | Lookup host information on Shodan |
| `recon_shodan_search` | Shodan API | Passive | Search Shodan for hosts matching criteria |
| `recon_shodan_dns` | Shodan API | Passive | DNS resolution via Shodan |
| `recon_subfinder` | `subfinder` | Passive | Subdomain enumeration via passive sources |
| `recon_nuclei` | `nuclei` | **Active** | Vulnerability scanning with templates |
| `recon_dnsx` | `dnsx` | Passive | DNS resolution & enumeration (supports wordlists) |
| `recon_httpx` | `httpx` | Passive | HTTP probing, tech detection, title extraction |
| `recon_katana` | `katana` | **Active** | Web crawling / endpoint discovery |
| `recon_theharvester` | `theHarvester` | Passive | Email, subdomain & IP OSINT |
| `recon_status` | — | Local | Checks which binaries, integrations, and API keys are available |

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

### Standalone HTTP Mode

```bash
# Default port 8000
python recon_mcp_server.py

# Custom port
python recon_mcp_server.py --port 9000

# Or via env var
RECON_MCP_PORT=9000 python recon_mcp_server.py
```

### Managed by Claude Desktop

When configured properly in `claude_desktop_config.json`, Claude Desktop will start and manage the server automatically. No manual startup needed.

## Client Configuration

### Claude Desktop (`claude_desktop_config.json`)

Claude Desktop requires a command-based configuration:

```json
{
  "mcpServers": {
    "recon_mcp": {
      "command": "python",
      "args": ["/path/to/your/project/recon_mcp_server.py"],
      "env": {
        "RECON_MCP_PORT": "8000"
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
    "recon_mcp": {
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
    "recon_mcp": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Or command-based:

```json
{
  "mcpServers": {
    "recon_mcp": {
      "command": "python",
      "args": ["./recon_mcp_server.py"]
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

> "Run subfinder on example.com, then pipe results to httpx to find live web servers"

> "Probe https://example.com with httpx and show technologies"

> "Use dnsx to bruteforce subdomains on example.com with dns_subdomains_top1000 wordlist"

**Vulnerability Scanning:**
> "Use nuclei to check example.com for critical and high severity vulnerabilities"

**Web Crawling:**
> "Crawl https://example.com with katana depth 3 and look for API endpoints"

**Status Check:**
> "Check recon_status to see which tools are installed"

## Security Notice

⚠️ **Authorization Required**: Tools marked **Active** (nuclei, katana) send requests to targets. Only use against systems you have explicit written authorization to test. Unauthorized scanning may violate laws including the CFAA.

The Google Dorking tool generates queries only — it does not execute searches to avoid Google ToS violations.
