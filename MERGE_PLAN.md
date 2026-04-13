# FieldKit MCP Merge Plan: Adding Web Browsing Surface

## Objective

Extend [fieldkit-mcp](https://github.com/ResistanceIsUseless/fieldkit-mcp) into a full "internet swiss army knife" MCP server. Keep all existing reconnaissance capabilities, add a web browsing/fetching surface, rename tools to objective-based commands, and package the whole thing for one-command setup.

**Primary goal:** single MCP server that gives Claude the same browsing + ASM surface an operator has, running in one container, callable from Claude Desktop and Claude Code.

**Explicitly out of scope for this merge:**
- Autotron integration (future phase)
- Authenticated browser sessions / persistent profiles
- Scheduled / daemon scanning
- Exploitation or payload delivery

---

## Tool Renaming — Objective-Based Commands

All tools rename to `verb_noun` describing *what the operator wants*, not *which binary runs*. The underlying implementation stays the same; only the MCP-exposed tool name and description change.

### Reconnaissance tools (existing — rename only)

| Current name | New name | Wraps |
|---|---|---|
| `recon_google_dork` | `dork_search` | DuckDuckGo / Google query builder |
| `recon_github_search` | `search_github_secrets` | GitHub API |
| `recon_trufflehog` | `hunt_secrets` | trufflehog |
| `recon_wayback` | `query_wayback` | Archive.org |
| `recon_shodan_host` | `lookup_shodan_host` | Shodan API |
| `recon_shodan_search` | `search_shodan` | Shodan API |
| `recon_shodan_dns` | `resolve_shodan_dns` | Shodan DNS |
| `recon_subfinder` | `discover_subdomains` | subfinder |
| `recon_nuclei` | `scan_vulnerabilities` | nuclei |
| `recon_dnsx` | `enumerate_dns` | dnsx |
| `recon_httpx` | `probe_http` | httpx |
| `recon_katana` | *(removed — superseded by `web_crawl`)* | — |
| `recon_theharvester` | `harvest_osint` | theHarvester |
| `recon_status` | `check_tool_status` | local |

### Web surface tools (new)

| New tool | Purpose | Backend |
|---|---|---|
| `web_search` | Internet search, returns ranked URLs + snippets | DuckDuckGo HTML (no key required) |
| `web_fetch` | Raw HTTP request with full header/method/body control. No JS. Ignores `robots.txt`. | `httpx` (python) |
| `web_render` | Headless Chromium — JS rendering, click/type/scroll action sequences | Playwright |
| `web_crawl` | BFS crawl from seed URL with scope, depth, include/exclude patterns. Replaces katana. | Playwright + internal BFS |
| `web_screenshot` | Full-page or viewport PNG of rendered page | Playwright |
| `web_extract` | Readability / CSS selector / XPath extraction from a URL or cached page | selectolax + readability-lxml |
| `fingerprint_tech` | Wappalyzer-style technology detection | python-Wappalyzer + header/JS heuristics |
| `query_cache` | Introspect the local fetch cache — list URLs, retrieve prior responses | sqlite |

### Why `web_crawl` replaces katana

Katana is an active endpoint-discovery tool; `web_crawl` is operator-intent crawling ("read these pages like I would"). Maintaining both creates ambiguity for Claude when picking tools. Collapsing to one — `web_crawl`, backed by Playwright so JS-rendered sites work — keeps the tool surface clean. Katana's binary can stay installed in the container if we want to swap backends later, but it is not exposed as an MCP tool.

---

## Robots.txt

All `web_*` tools ignore `robots.txt`. This is documented in each tool's MCP description so Claude does not apply its own assumptions. Per-host rate limiting is still enforced to avoid hammering servers — the limit is operator politeness, not robots compliance.

---

## File Layout

Minimal additions to the existing repo:

```
fieldkit-mcp/
├── fieldkit_mcp_server.py    # existing — add web_* tool registrations, update recon_* names
├── web_tools.py              # NEW — all web_* tool implementations in one file
├── cache.py                  # NEW — sqlite cache helper (small, could inline into web_tools.py)
├── requirements.txt          # UPDATED — add playwright, selectolax, readability-lxml, python-Wappalyzer
├── Dockerfile                # UPDATED — multi-stage build, Playwright base image
├── docker-compose.yml        # NEW — one-command run
├── .env.example              # NEW — all API keys documented in one place
├── install.sh                # NEW — native install script for non-Docker use
└── README.md                 # UPDATED — new tool names, setup instructions
```

Two new Python source files. Consistent with "don't create a ton of files."

---

## Dockerfile Strategy

Multi-stage build:

**Stage 1 — Go tool builder** (`golang:1.22-alpine`)
- `go install` subfinder, httpx, nuclei, dnsx, trufflehog
- Katana installed but not exposed (reserved for future backend swap)
- Produces static binaries copied into stage 2

**Stage 2 — Runtime** (`mcr.microsoft.com/playwright/python:v1.47-jammy`)
- Chromium + system deps pre-installed by base image
- Copy Go binaries from stage 1 into `/usr/local/bin`
- `pip install -r requirements.txt`
- `pip install theHarvester`
- Clone SecLists to `/opt/wordlists` (set `WORDLIST_DIR=/opt/wordlists/SecLists`)
- Expose port 8000
- Entrypoint: `python fieldkit_mcp_server.py`

Expected image size: ~1.5–2 GB. Everything runs out of the box; host needs only Docker.

---

## docker-compose.yml

```yaml
services:
  recon-mcp:
    build: .
    container_name: recon-mcp
    ports:
      - "8000:8000"
    env_file: .env
    volumes:
      - ./cache:/app/cache        # sqlite cache persists across restarts
      - ./output:/app/output      # screenshots, scan artifacts
    restart: unless-stopped
```

---

## .env.example

```bash
# Required for specific tools — leave blank to disable those tools
SHODAN_API_KEY=
GITHUB_TOKEN=

# Optional — expand passive source coverage
VIRUSTOTAL_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
CHAOS_API_KEY=

# Server config
FIELDKIT_MCP_PORT=8000
WORDLIST_DIR=/opt/wordlists/SecLists
CACHE_DB=/app/cache/cache.db
```

---

## One-Command Setup

**Docker (recommended):**
```bash
git clone https://github.com/ResistanceIsUseless/fieldkit-mcp
cd fieldkit-mcp
cp .env.example .env    # fill in keys you want
docker compose up -d
```

Server is now at `http://localhost:8000/mcp`.

**Native (for iterating on the server itself):**
```bash
./install.sh            # installs go tools, pip deps, playwright browsers, seclists
python fieldkit_mcp_server.py
```

`install.sh` replaces the multi-step README dance. It detects the platform, checks for Go/Python, installs missing dependencies, and exits cleanly with a summary.

---

## Client Configuration

### Claude Desktop

Edit `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

**Option A — Docker container running in background:**
```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:8000/mcp"]
    }
  }
}
```
(`mcp-remote` bridges stdio to the container's HTTP endpoint. Claude Desktop does not speak HTTP MCP directly yet.)

**Option B — Native install, Claude Desktop manages the process:**
```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "command": "python",
      "args": ["/absolute/path/to/fieldkit-mcp/fieldkit_mcp_server.py"],
      "env": {
        "FIELDKIT_MCP_PORT": "8000",
        "SHODAN_API_KEY": "...",
        "GITHUB_TOKEN": "..."
      }
    }
  }
}
```

Restart Claude Desktop after editing. Verify the server appears in the tools menu.

### Claude Code

Create `.mcp.json` in the project root (or edit `~/.claude/mcp.json` for global):

**Docker:**
```json
{
  "mcpServers": {
    "fieldkit_mcp": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Claude Code speaks HTTP MCP natively — no `mcp-remote` shim needed.

**Native:**
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

### Verifying the connection

After configuring, start a new chat and ask:
> "Run check_tool_status and tell me which tools are available."

If the server is wired correctly, Claude will list every binary and API key status.

### Other MCP clients (Cursor, Continue, etc.)

Point them at `http://localhost:8000/mcp`. Any client that supports the MCP streamable HTTP transport works without modification.

---

## Build Order

Each phase leaves the server in a working state. Stop at any point without breaking existing functionality.

1. **Rename existing recon tools.** Update `fieldkit_mcp_server.py` tool registrations to new objective-based names. Keep old names as deprecated aliases for one release to avoid breaking existing workflows. Update README table.

2. **Create `cache.py` + sqlite schema.** Single table: `(url TEXT PRIMARY KEY, method TEXT, status INT, headers JSON, body BLOB, fetched_at TIMESTAMP, content_hash TEXT)`. Used by `web_fetch`, `web_render`, `web_crawl`, `query_cache`.

3. **Create `web_tools.py` skeleton.** All eight `web_*` tools registered as stubs that raise `NotImplementedError("# STUB — see MERGE_PLAN.md phase N")`. Lets the server start with the new surface visible.

4. **Implement `web_fetch` + `query_cache`.** Smallest useful slice. Test end-to-end via Claude Code.

5. **Implement `web_render` + `web_screenshot`.** Playwright integration. Highest risk of bugs — isolate here. Test with JS-heavy sites (SPAs).

6. **Implement `web_crawl` + `web_extract` + `fingerprint_tech`.** Built on top of `web_render`. `web_crawl` uses Playwright for fetching but runs its own BFS queue with scope controls.

7. **Implement `web_search`.** DuckDuckGo HTML scrape. Simple, last because it is the least critical.

8. **Dockerfile + docker-compose.yml + install.sh + .env.example.** Package everything. Test the full one-command flow on a clean machine.

9. **Update README.md.** New tool names, new setup instructions, new client configs, migration note for the rename.

---

## Requirements.txt Additions

```
playwright>=1.47
selectolax>=0.3.21
readability-lxml>=0.8.1
python-Wappalyzer>=0.4.0
httpx>=0.27
```

Existing dependencies (fastmcp, shodan, etc.) unchanged.

---

## Open Questions for Future Phases

These are deliberately deferred — noted here so they do not get forgotten:

- **Autotron integration.** Wire as named workflow tools (`asm_discover`, `asm_enrich`, `asm_diff`) once autotron's interface is decided (CLI passthrough vs Go library import).
- **Auth'd browser sessions.** Persistent Playwright context for sites requiring login.
- **Result streaming.** Long crawls and scans currently block the tool call. MCP progress notifications would improve UX.
- **Search backend swap.** If DDG HTML scraping gets flaky, add SearXNG (self-hosted) or Brave API as alternate backends behind the same `web_search` tool.
