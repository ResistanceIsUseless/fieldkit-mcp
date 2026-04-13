#!/usr/bin/env python3
"""
fieldkit-mcp - Offensive Security Reconnaissance MCP Server

A Model Context Protocol server exposing search engine dorking, Shodan, and
ProjectDiscovery tools (subfinder, nuclei, dnsx, katana, httpx) plus theHarvester,
webscope, subscope, nmap, and trufflehog for LLM-driven reconnaissance workflows.

AUTHORIZATION NOTICE:
This server is designed for authorized security testing only. All reconnaissance
activities are performed against systems where explicit written authorization has
been obtained. Active scanning tools (nuclei, katana, webscope, nmap) should only
be used against systems you have permission to test.

Transport: Streamable HTTP (default port 8000) or stdio
Auth: API keys for external services via environment variables

Required tools (must be on PATH):
  - subfinder   (github.com/projectdiscovery/subfinder)
  - nuclei      (github.com/projectdiscovery/nuclei)
  - dnsx        (github.com/projectdiscovery/dnsx)
  - katana      (github.com/projectdiscovery/katana)
  - httpx       (github.com/projectdiscovery/httpx)
  - theHarvester (github.com/laramies/theHarvester)
  - webscope    (github.com/ResistanceIsUseless/webscope)
  - subscope    (github.com/ResistanceIsUseless/subscope)
  - nmap        (nmap.org)
  - trufflehog  (github.com/trufflesecurity/trufflehog)

Environment variables (optional, enhance results):
  - SHODAN_API_KEY (required for Shodan tools)
  - VIRUSTOTAL_API_KEY
  - CENSYS_API_ID / CENSYS_API_SECRET
  - CHAOS_API_KEY (ProjectDiscovery Chaos)
  - GITHUB_TOKEN  (for subfinder GitHub source)

Usage:
  pip install -r requirements.txt
  python fieldkit_mcp_server.py [--port 8000] [--stdio]
"""

import asyncio
import json
import logging
import os
import shutil
import sys
from enum import Enum
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator
import httpx

from cache import init_cache
from web_tools import register_web_tools

# Search engines and Shodan
try:
    from googlesearch import search as google_search
    GOOGLE_SEARCH_AVAILABLE = True
except ImportError:
    GOOGLE_SEARCH_AVAILABLE = False
    logger.warning("googlesearch-python not installed - Google search disabled")

try:
    from duckduckgo_search import DDGS
    DUCKDUCKGO_AVAILABLE = True
except ImportError:
    DUCKDUCKGO_AVAILABLE = False
    logger.warning("duckduckgo-search not installed - DuckDuckGo search disabled")

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logger.warning("shodan not installed - Shodan tools disabled")

# ---------------------------------------------------------------------------
# Logging — stderr only (stdout reserved for transport)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("fieldkit_mcp")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 300  # seconds — nuclei scans can be slow
MAX_OUTPUT_LINES = 200  # cap output to keep context manageable for LLMs
MAX_OUTPUT_CHARS = 12000  # hard cap on character count (~3k tokens)
SERVER_PORT = int(os.environ.get("FIELDKIT_MCP_PORT", os.environ.get("RECON_MCP_PORT", "8000")))

# Wordlist paths - can be overridden via environment variables
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", os.path.expanduser("~/.recon-wordlists"))
SECLISTS_DIR = os.path.join(WORDLIST_DIR, "SecLists")

# Common wordlist paths (relative to SECLISTS_DIR)
COMMON_WORDLISTS = {
    "dns_subdomains_top1000": "Discovery/DNS/subdomains-top1million-5000.txt",
    "dns_subdomains_top20k": "Discovery/DNS/subdomains-top1million-20000.txt",
    "dns_subdomains_top110k": "Discovery/DNS/subdomains-top1million-110000.txt",
    "dns_fierce": "Discovery/DNS/fierce-hostlist.txt",
    "dns_bitquark": "Discovery/DNS/bitquark-subdomains-top100000.txt",
}

# ---------------------------------------------------------------------------
# Server Init
# ---------------------------------------------------------------------------
# Check if we should use stdio mode (for Claude Desktop) or HTTP mode
USE_STDIO = os.environ.get("MCP_TRANSPORT", "").lower() == "stdio"
mcp = FastMCP("fieldkit-mcp") if USE_STDIO else FastMCP("fieldkit-mcp", port=SERVER_PORT)
init_cache()
register_web_tools(mcp)

# ---------------------------------------------------------------------------
# Shared Models
# ---------------------------------------------------------------------------

class ResponseFormat(str, Enum):
    """Output format for tool responses."""
    MARKDOWN = "markdown"
    JSON = "json"


# ---------------------------------------------------------------------------
# Shared Helpers
# ---------------------------------------------------------------------------

def _get_wordlist_path(wordlist_name: str) -> Optional[str]:
    """
    Get the full path to a wordlist.

    Args:
        wordlist_name: Either a wordlist alias (e.g., 'dns_subdomains_top1000')
                      or a direct file path.

    Returns:
        Full path to wordlist if it exists, None otherwise.
    """
    # If it's a direct path and exists, return it
    if os.path.isfile(wordlist_name):
        return wordlist_name

    # Check if it's a common wordlist alias
    if wordlist_name in COMMON_WORDLISTS:
        wordlist_path = os.path.join(SECLISTS_DIR, COMMON_WORDLISTS[wordlist_name])
        if os.path.isfile(wordlist_path):
            return wordlist_path
        else:
            logger.warning(f"Wordlist '{wordlist_name}' not found at {wordlist_path}")
            logger.info(f"To install SecLists: git clone https://github.com/danielmiessler/SecLists.git {SECLISTS_DIR}")
            return None

    # Check if it's a path relative to WORDLIST_DIR
    wordlist_path = os.path.join(WORDLIST_DIR, wordlist_name)
    if os.path.isfile(wordlist_path):
        return wordlist_path

    logger.warning(f"Wordlist not found: {wordlist_name}")
    return None


def _check_binary(name: str) -> str:
    """
    Verify a binary exists on PATH. Returns the resolved path.
    Raises a clear error if missing so the LLM can report it.

    For ProjectDiscovery tools, prioritize pdtm installation over other paths
    to avoid conflicts (e.g., Python httpx vs PD httpx).
    """
    # ProjectDiscovery tools - check pdtm directory first
    pd_tools = ["subfinder", "nuclei", "dnsx", "httpx", "katana"]
    if name in pd_tools:
        pdtm_path = os.path.expanduser(f"~/.pdtm/go/bin/{name}")
        if os.path.isfile(pdtm_path) and os.access(pdtm_path, os.X_OK):
            return pdtm_path

    # Fall back to standard PATH lookup
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(
            f"Required binary '{name}' not found on PATH. "
            f"Install it before using this tool. "
            f"See the server docstring for install links."
        )
    return path


async def _run_command(
    cmd: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    stdin_data: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute a subprocess asynchronously and return structured output.

    Returns:
        dict with keys: stdout, stderr, returncode, timed_out
    """
    logger.info("Executing: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
        return {
            "stdout": stdout_bytes.decode(errors="replace"),
            "stderr": stderr_bytes.decode(errors="replace"),
            "returncode": proc.returncode,
            "timed_out": False,
        }
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "returncode": -1,
            "timed_out": True,
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Execution error: {type(e).__name__}: {e}",
            "returncode": -1,
            "timed_out": False,
        }


def _truncate_output(
    text: str,
    max_lines: int = MAX_OUTPUT_LINES,
    max_chars: int = MAX_OUTPUT_CHARS,
) -> str:
    """Truncate output by line count AND character count to prevent LLM context overflow."""
    lines = text.splitlines()
    total_lines = len(lines)

    # First pass: line limit
    if total_lines > max_lines:
        lines = lines[:max_lines]

    # Second pass: character limit
    truncated_lines = []
    char_count = 0
    for line in lines:
        if char_count + len(line) + 1 > max_chars:
            break
        truncated_lines.append(line)
        char_count += len(line) + 1

    result = "\n".join(truncated_lines)
    omitted = total_lines - len(truncated_lines)
    if omitted > 0:
        result += f"\n\n[... truncated — {omitted} of {total_lines} lines omitted to fit LLM context]"
    return result


def _smart_summarize_json(text: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Attempt to parse JSON-lines output and return a compact summary.

    Many recon tools emit one JSON object per line. Instead of dumping
    everything, count items and show a representative sample.
    """
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return text

    parsed = []
    for line in lines:
        try:
            parsed.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            # Not JSON-lines — fall back to plain truncation
            return _truncate_output(text, max_chars=max_chars)

    total = len(parsed)
    # Show first N items that fit in budget
    sample = []
    running = 0
    budget = max_chars - 200  # leave room for summary header
    for item in parsed:
        rendered = json.dumps(item, indent=2)
        if running + len(rendered) > budget:
            break
        sample.append(rendered)
        running += len(rendered)

    parts = [f"Total items: {total}"]
    if len(sample) < total:
        parts.append(f"Showing first {len(sample)} of {total}:")
    parts.extend(sample)
    if len(sample) < total:
        parts.append(f"\n[... {total - len(sample)} more items omitted]")
    return "\n".join(parts)


def _format_result(
    result: Dict[str, Any],
    tool_name: str,
    fmt: ResponseFormat,
) -> str:
    """
    Unified formatter for subprocess results.
    Markdown mode gives a readable summary; JSON mode returns raw structure.
    Both modes enforce output size limits to prevent LLM context overflow.
    """
    if fmt == ResponseFormat.JSON:
        raw = json.dumps(result, indent=2)
        if len(raw) > MAX_OUTPUT_CHARS:
            # Summarize instead of dumping a massive blob
            return _smart_summarize_json(result["stdout"])
        return raw

    # --- Markdown ---
    output = _truncate_output(result["stdout"]).strip()
    errors = _truncate_output(result["stderr"], max_lines=30, max_chars=2000).strip()

    parts = [f"## {tool_name} Results\n"]

    if result["timed_out"]:
        parts.append("> ⚠️ **Command timed out.** Partial results may appear below.\n")

    if result["returncode"] != 0 and not result["timed_out"]:
        parts.append(f"> ⚠️ Exit code **{result['returncode']}**\n")

    # Add line count context
    total_lines = len(result["stdout"].splitlines()) if result["stdout"] else 0
    if total_lines > 0:
        parts.append(f"**Total output lines:** {total_lines}\n")

    if output:
        parts.append(f"```\n{output}\n```")
    else:
        parts.append("_No output returned._")

    if errors:
        parts.append(f"\n### Stderr\n```\n{errors}\n```")

    return "\n".join(parts)


# =========================================================================
# TOOL 1 — Search Engine Dorking (Google, DuckDuckGo, both)
# =========================================================================

class GoogleDorkInput(BaseModel):
    """Input for constructing and executing search engine dork queries."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    # Core target
    domain: Optional[str] = Field(
        default=None,
        description="Target domain to scope the dork (e.g., 'example.com')",
        max_length=253,
    )

    # Dork operators — each maps to a Google search operator
    search_term: Optional[str] = Field(
        default=None,
        description="Free-text search keywords to include",
        max_length=500,
    )
    filetype: Optional[str] = Field(
        default=None,
        description="File extension to search for (e.g., 'pdf', 'xlsx', 'sql', 'env', 'log')",
        max_length=20,
    )
    inurl: Optional[str] = Field(
        default=None,
        description="String that must appear in the URL (e.g., 'admin', 'login', 'wp-content')",
        max_length=200,
    )
    intitle: Optional[str] = Field(
        default=None,
        description="String that must appear in the page title (e.g., 'index of', 'dashboard')",
        max_length=200,
    )
    intext: Optional[str] = Field(
        default=None,
        description="String that must appear in the page body (e.g., 'password', 'api_key')",
        max_length=200,
    )
    ext: Optional[str] = Field(
        default=None,
        description="Alternative file extension operator (e.g., 'xml', 'conf')",
        max_length=20,
    )
    exclude_domain: Optional[str] = Field(
        default=None,
        description="Domain to exclude from results (e.g., 'www.example.com')",
        max_length=253,
    )
    cache: Optional[str] = Field(
        default=None,
        description="URL to view Google's cached version of",
        max_length=500,
    )
    raw_operators: Optional[str] = Field(
        default=None,
        description="Any additional raw Google operators to append verbatim",
        max_length=500,
    )

    # Preset categories for common recon dork patterns
    preset: Optional[str] = Field(
        default=None,
        description=(
            "Use a pre-built dork category instead of manual operators. "
            "Options: 'sensitive_files' (env/sql/log/bak), "
            "'login_pages' (admin/login portals), "
            "'directory_listings' (open indexes), "
            "'exposed_documents' (pdf/docx/xlsx), "
            "'error_messages' (stack traces, SQL errors), "
            "'config_files' (xml/conf/ini/yaml), "
            "'api_endpoints' (swagger/graphql/api paths), "
            "'cloud_exposure' (S3/Azure/GCS buckets)"
        ),
    )

    execute_search: bool = Field(
        default=True,
        description="Execute the search and return live results. Set to False to only build query strings. NOTE: User has confirmed authorization for all target systems.",
    )

    search_engine: str = Field(
        default="duckduckgo",
        description="Search engine to use: 'google', 'duckduckgo', or 'both'. DuckDuckGo recommended for avoiding rate limits.",
    )

    max_results: int = Field(
        default=10,
        description="Maximum number of search results to return per query when execute_search is True",
        ge=1,
        le=50,
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


# Preset dork templates keyed by category name
_DORK_PRESETS: Dict[str, List[str]] = {
    "sensitive_files": [
        'filetype:env "DB_PASSWORD"',
        'filetype:sql "insert into"',
        'filetype:log "password"',
        'filetype:bak inurl:admin',
        'filetype:cfg "password"',
    ],
    "login_pages": [
        'intitle:"login" inurl:admin',
        'intitle:"dashboard" inurl:login',
        'inurl:"/wp-login.php"',
        'intitle:"sign in" inurl:auth',
    ],
    "directory_listings": [
        'intitle:"index of /"',
        'intitle:"index of" "parent directory"',
        'intitle:"index of" inurl:backup',
    ],
    "exposed_documents": [
        'filetype:pdf "confidential"',
        'filetype:docx "internal use only"',
        'filetype:xlsx "password"',
        'filetype:pptx "not for distribution"',
    ],
    "error_messages": [
        '"Fatal error" "on line"',
        '"SQL syntax" "mysql"',
        '"stack trace" "exception"',
        'inurl:debug "traceback"',
    ],
    "config_files": [
        'filetype:xml "password"',
        'filetype:conf inurl:etc',
        'filetype:ini "[database]"',
        'filetype:yaml "api_key"',
    ],
    "api_endpoints": [
        'inurl:"/swagger" intitle:"swagger"',
        'inurl:"/graphql"',
        'inurl:"/api/v1" intitle:"index"',
        'inurl:"/openapi.json"',
    ],
    "cloud_exposure": [
        'site:s3.amazonaws.com',
        'site:blob.core.windows.net',
        'site:storage.googleapis.com',
        'inurl:".s3.amazonaws.com" "index of"',
    ],
}


@mcp.tool(
    name="dork_search",
    annotations={
        "title": "Search Engine Dorking (Google, DuckDuckGo)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,  # Executes web searches by default
    },
)
async def dork_search(params: GoogleDorkInput) -> str:
    """Build and execute search engine dork queries for passive reconnaissance.

    Constructs search dork strings using standard operators (site, filetype, inurl,
    intitle, intext, etc.) or preset categories scoped to a target domain. Executes
    searches by default using DuckDuckGo, Google, or both engines.

    All searches are performed against authorized target systems only.

    Args:
        params (GoogleDorkInput): Dork configuration with operators, preset, and search engine.

    Returns:
        str: Search results with URLs, titles, and snippets (Markdown or JSON).
    """
    queries: List[str] = []

    # --- Preset mode ---
    if params.preset:
        key = params.preset.lower().strip()
        if key not in _DORK_PRESETS:
            return (
                f"Error: Unknown preset '{params.preset}'. "
                f"Available: {', '.join(sorted(_DORK_PRESETS.keys()))}"
            )
        for dork in _DORK_PRESETS[key]:
            # Scope to domain if provided
            q = f"site:{params.domain} {dork}" if params.domain else dork
            queries.append(q)
    else:
        # --- Manual operator mode ---
        parts: List[str] = []
        if params.domain:
            parts.append(f"site:{params.domain}")
        if params.filetype:
            parts.append(f"filetype:{params.filetype}")
        if params.ext:
            parts.append(f"ext:{params.ext}")
        if params.inurl:
            parts.append(f"inurl:{params.inurl}")
        if params.intitle:
            parts.append(f'intitle:"{params.intitle}"')
        if params.intext:
            parts.append(f'intext:"{params.intext}"')
        if params.exclude_domain:
            parts.append(f"-site:{params.exclude_domain}")
        if params.cache:
            parts.append(f"cache:{params.cache}")
        if params.search_term:
            parts.append(params.search_term)
        if params.raw_operators:
            parts.append(params.raw_operators)

        if not parts:
            return "Error: Provide at least one operator, a search_term, or a preset."
        queries.append(" ".join(parts))

    # --- Execute searches if requested ---
    search_results = {}
    if params.execute_search:
        engine = params.search_engine.lower().strip()

        # Validate search engine availability
        if engine in ("google", "both") and not GOOGLE_SEARCH_AVAILABLE:
            return "Error: Google search requires 'googlesearch-python' package. Install with: pip install googlesearch-python"
        if engine in ("duckduckgo", "both") and not DUCKDUCKGO_AVAILABLE:
            return "Error: DuckDuckGo search requires 'duckduckgo-search' package. Install with: pip install duckduckgo-search"

        logger.info(f"Executing {len(queries)} search(es) using {engine}")

        for query in queries:
            search_results[query] = {}

            # DuckDuckGo search
            if engine in ("duckduckgo", "both"):
                try:
                    ddg_results = []
                    with DDGS() as ddgs:
                        for result in ddgs.text(query, max_results=params.max_results):
                            ddg_results.append({
                                "url": result.get("href", result.get("link", "")),
                                "title": result.get("title", ""),
                                "snippet": result.get("body", result.get("snippet", ""))
                            })
                    search_results[query]["duckduckgo"] = ddg_results
                    logger.info(f"DuckDuckGo: Found {len(ddg_results)} results for: {query}")
                except Exception as e:
                    logger.error(f"DuckDuckGo search failed for '{query}': {e}")
                    search_results[query]["duckduckgo"] = {"error": str(e)}

            # Google search
            if engine in ("google", "both"):
                try:
                    google_results = []
                    for url in google_search(query, num_results=params.max_results, sleep_interval=2):
                        google_results.append({"url": url})
                    search_results[query]["google"] = google_results
                    logger.info(f"Google: Found {len(google_results)} results for: {query}")
                except Exception as e:
                    logger.error(f"Google search failed for '{query}': {e}")
                    search_results[query]["google"] = {"error": str(e)}

    # --- Format output ---
    if params.response_format == ResponseFormat.JSON:
        output = {
            "tool": "dork_search",
            "domain": params.domain,
            "preset": params.preset,
            "queries": queries,
        }
        if params.execute_search:
            output["results"] = search_results
            output["warning"] = "Automated Google searches may violate Google ToS if overused"
        else:
            output["usage_note"] = "Execute these queries in a browser. Set execute_search=True to run automatically."
        return json.dumps(output, indent=2)

    lines = [f"## Search Dork Queries ({params.search_engine.upper() if params.execute_search else 'N/A'})\n"]
    if params.domain:
        lines.append(f"**Target domain:** `{params.domain}`\n")
    if params.preset:
        lines.append(f"**Preset category:** `{params.preset}`\n")

    if not params.execute_search:
        for i, q in enumerate(queries, 1):
            lines.append(f"{i}. `{q}`")
        lines.append(
            "\n> **Note:** Set `execute_search=True` to run searches automatically (default). "
            "All searches are against authorized systems only."
        )
    else:
        # Display results from multiple search engines
        for query in queries:
            lines.append(f"\n### Query: `{query}`\n")
            if query in search_results:
                query_results = search_results[query]

                # DuckDuckGo results
                if "duckduckgo" in query_results:
                    lines.append("#### 🦆 DuckDuckGo Results\n")
                    ddg_data = query_results["duckduckgo"]
                    if isinstance(ddg_data, dict) and "error" in ddg_data:
                        lines.append(f"❌ Error: {ddg_data['error']}\n")
                    elif ddg_data:
                        for i, result in enumerate(ddg_data, 1):
                            title = result.get("title", "No title")
                            url = result.get("url", "")
                            snippet = result.get("snippet", "")
                            lines.append(f"{i}. **{title}**")
                            lines.append(f"   {url}")
                            if snippet:
                                lines.append(f"   _{snippet[:150]}..._\n")
                    else:
                        lines.append("_No results found_\n")

                # Google results
                if "google" in query_results:
                    lines.append("#### 🔍 Google Results\n")
                    google_data = query_results["google"]
                    if isinstance(google_data, dict) and "error" in google_data:
                        lines.append(f"❌ Error: {google_data['error']}\n")
                    elif google_data:
                        for i, result in enumerate(google_data, 1):
                            url = result.get("url", "")
                            lines.append(f"{i}. {url}")
                    else:
                        lines.append("_No results found_\n")

        lines.append(
            "\n> ✅ **Authorization:** All searches performed against authorized target systems only."
        )

    return "\n".join(lines)


@mcp.tool(
    name="recon_google_dork",
    annotations={
        "title": "DEPRECATED: Use dork_search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_google_dork(params: GoogleDorkInput) -> str:
    """Deprecated alias for dork_search."""
    return await dork_search(params)


# =========================================================================
# TOOL 2 — subfinder (subdomain enumeration)
# =========================================================================

class SubfinderInput(BaseModel):
    """Input for ProjectDiscovery subfinder."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    domain: str = Field(
        ...,
        description="Target domain for subdomain enumeration (e.g., 'example.com')",
        min_length=3,
        max_length=253,
    )
    recursive: bool = Field(
        default=False,
        description="Enable recursive subdomain enumeration",
    )
    sources: Optional[str] = Field(
        default=None,
        description="Comma-separated list of sources to use (e.g., 'crtsh,hackertarget,virustotal')",
        max_length=500,
    )
    exclude_sources: Optional[str] = Field(
        default=None,
        description="Comma-separated sources to exclude",
        max_length=500,
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Timeout in seconds",
        ge=10,
        le=600,
    )
    max_results: Optional[int] = Field(
        default=None,
        description="Maximum number of subdomains to return",
        ge=1,
        le=10000,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Basic domain validation — no protocol, no path."""
        v = v.strip().lower()
        if v.startswith(("http://", "https://")):
            v = v.split("//", 1)[1]
        v = v.split("/")[0]
        return v


@mcp.tool(
    name="discover_subdomains",
    annotations={
        "title": "Subfinder — Subdomain Enumeration",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def discover_subdomains(params: SubfinderInput) -> str:
    """Enumerate subdomains for a target domain using ProjectDiscovery subfinder.

    Queries multiple passive sources (crt.sh, VirusTotal, Shodan, etc.)
    to discover subdomains. Does NOT send traffic to the target — purely
    passive OSINT collection.

    Args:
        params (SubfinderInput): Enumeration configuration.

    Returns:
        str: Discovered subdomains (Markdown or JSON).
    """
    _check_binary("subfinder")

    cmd = ["subfinder", "-d", params.domain, "-silent"]

    if params.recursive:
        cmd.append("-recursive")
    if params.sources:
        cmd.extend(["-sources", params.sources])
    if params.exclude_sources:
        cmd.extend(["-exclude-sources", params.exclude_sources])

    result = await _run_command(cmd, timeout=params.timeout)

    # Post-process: deduplicate and optionally cap results
    if result["stdout"]:
        subs = sorted(set(line.strip() for line in result["stdout"].splitlines() if line.strip()))
        if params.max_results and len(subs) > params.max_results:
            subs = subs[: params.max_results]
        result["stdout"] = "\n".join(subs)
        result["count"] = len(subs)
    else:
        result["count"] = 0

    return _format_result(result, "subfinder", params.response_format)


@mcp.tool(
    name="recon_subfinder",
    annotations={
        "title": "DEPRECATED: Use discover_subdomains",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_subfinder(params: SubfinderInput) -> str:
    """Deprecated alias for discover_subdomains."""
    return await discover_subdomains(params)


# =========================================================================
# TOOL 3 — nuclei (vulnerability scanning)
# =========================================================================

class NucleiSeverity(str, Enum):
    """Nuclei template severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NucleiInput(BaseModel):
    """Input for ProjectDiscovery nuclei."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    target: str = Field(
        ...,
        description="Target URL or host (e.g., 'https://example.com' or 'example.com')",
        min_length=3,
        max_length=500,
    )
    target_list_stdin: Optional[str] = Field(
        default=None,
        description="Newline-separated list of targets to pipe via stdin (for bulk scanning)",
        max_length=50000,
    )
    templates: Optional[str] = Field(
        default=None,
        description="Comma-separated template IDs or paths (e.g., 'cves,misconfigurations')",
        max_length=1000,
    )
    tags: Optional[str] = Field(
        default=None,
        description="Comma-separated tags to filter templates (e.g., 'cve,rce,sqli,xss,lfi')",
        max_length=500,
    )
    severity: Optional[List[NucleiSeverity]] = Field(
        default=None,
        description="Filter templates by severity (e.g., ['high', 'critical'])",
    )
    exclude_tags: Optional[str] = Field(
        default=None,
        description="Comma-separated tags to exclude (e.g., 'dos,fuzz')",
        max_length=500,
    )
    rate_limit: int = Field(
        default=150,
        description="Maximum requests per second",
        ge=1,
        le=1000,
    )
    concurrency: int = Field(
        default=25,
        description="Number of concurrent template executions",
        ge=1,
        le=100,
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Overall execution timeout in seconds",
        ge=30,
        le=1800,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="scan_vulnerabilities",
    annotations={
        "title": "Nuclei — Vulnerability Scanner",
        "readOnlyHint": False,  # Sends probes to target
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def scan_vulnerabilities(params: NucleiInput) -> str:
    """Scan targets for vulnerabilities using ProjectDiscovery nuclei.

    Runs nuclei with the specified templates/tags/severity filters against
    the target. This is an ACTIVE scanning tool — it sends HTTP requests to
    the target.

    ⚠️ Only use against targets you have explicit authorization to test.

    Args:
        params (NucleiInput): Scan configuration.

    Returns:
        str: Scan findings (Markdown or JSON).
    """
    _check_binary("nuclei")

    cmd = ["nuclei", "-silent", "-nc"]  # -nc = no color codes

    # Target: stdin list takes precedence
    if not params.target_list_stdin:
        cmd.extend(["-u", params.target])

    if params.templates:
        cmd.extend(["-t", params.templates])
    if params.tags:
        cmd.extend(["-tags", params.tags])
    if params.severity:
        cmd.extend(["-severity", ",".join(s.value for s in params.severity)])
    if params.exclude_tags:
        cmd.extend(["-exclude-tags", params.exclude_tags])
    cmd.extend(["-rl", str(params.rate_limit)])
    cmd.extend(["-c", str(params.concurrency)])

    result = await _run_command(
        cmd,
        timeout=params.timeout,
        stdin_data=params.target_list_stdin if params.target_list_stdin else None,
    )

    return _format_result(result, "nuclei", params.response_format)


@mcp.tool(
    name="recon_nuclei",
    annotations={
        "title": "DEPRECATED: Use scan_vulnerabilities",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_nuclei(params: NucleiInput) -> str:
    """Deprecated alias for scan_vulnerabilities."""
    return await scan_vulnerabilities(params)


# =========================================================================
# TOOL 4 — dnsx (DNS resolution & enumeration)
# =========================================================================

class DnsRecordType(str, Enum):
    """DNS record types supported by dnsx."""
    A = "a"
    AAAA = "aaaa"
    CNAME = "cname"
    MX = "mx"
    NS = "ns"
    TXT = "txt"
    SOA = "soa"
    PTR = "ptr"
    CAA = "caa"
    ANY = "any"


class DnsxInput(BaseModel):
    """Input for ProjectDiscovery dnsx."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    domain: Optional[str] = Field(
        default=None,
        description="Single domain/subdomain to resolve (e.g., 'example.com')",
        max_length=253,
    )
    domain_list_stdin: Optional[str] = Field(
        default=None,
        description="Newline-separated list of domains to pipe via stdin (for bulk resolution)",
        max_length=50000,
    )
    record_types: Optional[List[DnsRecordType]] = Field(
        default=None,
        description="DNS record types to query (default: A). Use multiple for comprehensive info.",
    )
    wordlist: Optional[str] = Field(
        default=None,
        description="Path to wordlist for subdomain brute-forcing",
        max_length=500,
    )
    wildcard_filtering: bool = Field(
        default=True,
        description="Enable wildcard domain filtering (recommended)",
    )
    resp_only: bool = Field(
        default=False,
        description="Show only response values (no domain prefix)",
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Timeout in seconds",
        ge=10,
        le=600,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="enumerate_dns",
    annotations={
        "title": "dnsx — DNS Resolution & Enumeration",
        "readOnlyHint": True,  # DNS queries only
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def enumerate_dns(params: DnsxInput) -> str:
    """Resolve and enumerate DNS records using ProjectDiscovery dnsx.

    Performs DNS resolution for one or many domains. Can query multiple
    record types and filter wildcard domains. Useful for mapping
    infrastructure after subdomain enumeration.

    Args:
        params (DnsxInput): DNS query configuration.

    Returns:
        str: DNS resolution results (Markdown or JSON).
    """
    _check_binary("dnsx")

    cmd = ["dnsx", "-silent"]

    # Input: stdin list or single domain
    stdin_data = None
    if params.domain_list_stdin:
        stdin_data = params.domain_list_stdin
    elif params.domain:
        stdin_data = params.domain
    else:
        return "Error: Provide either 'domain' or 'domain_list_stdin'."

    # Record types
    if params.record_types:
        for rt in params.record_types:
            cmd.append(f"-{rt.value}")

    if params.wordlist:
        wordlist_path = _get_wordlist_path(params.wordlist)
        if wordlist_path:
            cmd.extend(["-w", wordlist_path])
        else:
            return f"Error: Wordlist not found: {params.wordlist}. Available aliases: {', '.join(COMMON_WORDLISTS.keys())}"
    if not params.wildcard_filtering:
        cmd.append("-wd")  # disable wildcard detection
    if params.resp_only:
        cmd.append("-resp-only")

    result = await _run_command(cmd, timeout=params.timeout, stdin_data=stdin_data)

    return _format_result(result, "dnsx", params.response_format)


@mcp.tool(
    name="recon_dnsx",
    annotations={
        "title": "DEPRECATED: Use enumerate_dns",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_dnsx(params: DnsxInput) -> str:
    """Deprecated alias for enumerate_dns."""
    return await enumerate_dns(params)


# =========================================================================
# TOOL 5 — katana (web crawler / spider)
# =========================================================================

class KatanaInput(BaseModel):
    """Input for ProjectDiscovery katana."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    target: str = Field(
        ...,
        description="Target URL to crawl (e.g., 'https://example.com')",
        min_length=5,
        max_length=500,
    )
    depth: int = Field(
        default=2,
        description="Maximum crawl depth",
        ge=1,
        le=10,
    )
    js_crawl: bool = Field(
        default=False,
        description="Enable JavaScript parsing / headless crawling for SPA discovery",
    )
    scope_domain: Optional[str] = Field(
        default=None,
        description="Regex to restrict crawling scope (e.g., '.*\\.example\\.com')",
        max_length=500,
    )
    extensions_filter: Optional[str] = Field(
        default=None,
        description="Comma-separated file extensions to match (e.g., 'js,php,aspx')",
        max_length=200,
    )
    exclude_extensions: Optional[str] = Field(
        default=None,
        description="Comma-separated extensions to skip (e.g., 'png,jpg,gif,css')",
        max_length=200,
    )
    crawl_duration: Optional[int] = Field(
        default=None,
        description="Maximum crawl duration in seconds",
        ge=5,
        le=600,
    )
    concurrency: int = Field(
        default=10,
        description="Number of concurrent crawlers",
        ge=1,
        le=50,
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Overall execution timeout in seconds",
        ge=30,
        le=600,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="web_crawl",
    annotations={
        "title": "Web Crawl",
        "readOnlyHint": False,  # Actively crawls target
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def web_crawl(params: KatanaInput) -> str:
    """Crawl a target website to discover endpoints, URLs, and JavaScript files.

    Current backend uses ProjectDiscovery katana. This tool intentionally exposes
    objective-based naming (`web_crawl`) while preserving compatibility with the
    existing crawler backend.

    ⚠️ This is an ACTIVE tool — it sends HTTP requests to the target.
    Only use against targets you have explicit authorization to test.

    Args:
        params (KatanaInput): Crawl configuration.

    Returns:
        str: Discovered URLs and endpoints (Markdown or JSON).
    """
    _check_binary("katana")

    cmd = ["katana", "-u", params.target, "-silent", "-nc"]
    cmd.extend(["-d", str(params.depth)])
    cmd.extend(["-c", str(params.concurrency)])

    if params.js_crawl:
        cmd.append("-jc")
    if params.scope_domain:
        cmd.extend(["-cs", params.scope_domain])
    if params.extensions_filter:
        cmd.extend(["-em", params.extensions_filter])
    if params.exclude_extensions:
        cmd.extend(["-ef", params.exclude_extensions])
    if params.crawl_duration:
        cmd.extend(["-ct", str(params.crawl_duration)])

    result = await _run_command(cmd, timeout=params.timeout)

    # Post-process: deduplicate URLs
    if result["stdout"]:
        urls = sorted(set(line.strip() for line in result["stdout"].splitlines() if line.strip()))
        result["stdout"] = "\n".join(urls)
        result["count"] = len(urls)
    else:
        result["count"] = 0

    return _format_result(result, "katana", params.response_format)


@mcp.tool(
    name="recon_katana",
    annotations={
        "title": "DEPRECATED: Use web_crawl",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_katana(params: KatanaInput) -> str:
    """Deprecated alias for web_crawl."""
    return await web_crawl(params)


# =========================================================================
# TOOL 6 — httpx (HTTP probing & technology detection)
# =========================================================================

class HttpxInput(BaseModel):
    """Input for ProjectDiscovery httpx."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: Optional[str] = Field(
        default=None,
        description="Single URL to probe (e.g., 'https://example.com' or 'example.com')",
        max_length=500,
    )
    url_list_stdin: Optional[str] = Field(
        default=None,
        description="Newline-separated list of URLs/hosts to pipe via stdin (for bulk probing)",
        max_length=100000,
    )
    status_code: bool = Field(
        default=True,
        description="Display HTTP status code",
    )
    title: bool = Field(
        default=True,
        description="Display page title",
    )
    tech_detect: bool = Field(
        default=True,
        description="Detect web technologies (Wappalyzer-style)",
    )
    web_server: bool = Field(
        default=True,
        description="Display web server name",
    )
    content_length: bool = Field(
        default=False,
        description="Display content length",
    )
    follow_redirects: bool = Field(
        default=True,
        description="Follow HTTP redirects",
    )
    match_code: Optional[str] = Field(
        default=None,
        description="Filter by status codes (e.g., '200,301,302')",
        max_length=100,
    )
    filter_code: Optional[str] = Field(
        default=None,
        description="Exclude specific status codes (e.g., '404,403')",
        max_length=100,
    )
    threads: int = Field(
        default=50,
        description="Number of concurrent threads",
        ge=1,
        le=300,
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Timeout in seconds",
        ge=10,
        le=600,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="probe_http",
    annotations={
        "title": "httpx — HTTP Probing & Tech Detection",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def probe_http(params: HttpxInput) -> str:
    """Probe HTTP/HTTPS servers and detect technologies.

    Fast HTTP toolkit that probes for working web servers, extracts titles,
    detects technologies (CMS, frameworks, servers), and shows status codes.
    Perfect for validating subdomains found by subfinder or checking URL lists.

    Args:
        params (HttpxInput): Target URL(s) and probing options.

    Returns:
        str: HTTP probe results with status, title, and technologies (Markdown or JSON).
    """
    _check_binary("httpx")

    cmd = ["httpx", "-silent", "-json"]

    # Input handling
    if not params.url and not params.url_list_stdin:
        return "Error: Provide either 'url' or 'url_list_stdin'"

    # Output fields
    if params.status_code:
        cmd.append("-status-code")
    if params.title:
        cmd.append("-title")
    if params.tech_detect:
        cmd.append("-tech-detect")
    if params.web_server:
        cmd.append("-web-server")
    if params.content_length:
        cmd.append("-content-length")

    # Options
    if params.follow_redirects:
        cmd.append("-follow-redirects")

    if params.match_code:
        cmd.extend(["-match-code", params.match_code])
    if params.filter_code:
        cmd.extend(["-filter-code", params.filter_code])

    cmd.extend(["-threads", str(params.threads)])
    cmd.extend(["-timeout", str(params.timeout)])

    # Single URL mode
    if params.url:
        url = params.url if params.url.startswith(("http://", "https://")) else f"http://{params.url}"
        cmd.extend(["-u", url])

    result = await _run_command(
        cmd,
        timeout=params.timeout,
        stdin_data=params.url_list_stdin,
    )

    # Parse JSON output
    results = []
    if result["stdout"]:
        for line in result["stdout"].strip().split("\n"):
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if params.response_format == ResponseFormat.JSON:
        return json.dumps({
            "tool": "probe_http",
            "total_probed": len(results),
            "results": results
        }, indent=2)

    # Format as markdown
    lines = ["## httpx — HTTP Probe Results\n"]
    lines.append(f"**Total probed:** {len(results)}\n")

    if not results:
        lines.append("_No results found_")
    else:
        for i, item in enumerate(results, 1):
            url = item.get("url", "Unknown")
            status = item.get("status_code", "N/A")
            title = item.get("title", "")
            server = item.get("webserver", "")
            tech = item.get("tech", [])

            # Status indicator
            if str(status).startswith("2"):
                status_icon = "🟢"
            elif str(status).startswith("3"):
                status_icon = "🟡"
            elif str(status).startswith("4"):
                status_icon = "🔴"
            elif str(status).startswith("5"):
                status_icon = "🔴"
            else:
                status_icon = "⚪"

            lines.append(f"\n### {i}. {status_icon} {url}")
            lines.append(f"**Status:** {status}")

            if title:
                lines.append(f"**Title:** {title}")
            if server:
                lines.append(f"**Server:** {server}")
            if tech:
                tech_str = ", ".join(tech) if isinstance(tech, list) else tech
                lines.append(f"**Technologies:** {tech_str}")

            # Show content length if available
            if params.content_length and item.get("content_length"):
                lines.append(f"**Size:** {item['content_length']} bytes")

    return "\n".join(lines)


@mcp.tool(
    name="recon_httpx",
    annotations={
        "title": "DEPRECATED: Use probe_http",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_httpx(params: HttpxInput) -> str:
    """Deprecated alias for probe_http."""
    return await probe_http(params)


# =========================================================================
# TOOL 7 — theHarvester (email, name, subdomain, IP OSINT)
# =========================================================================

class HarvesterSource(str, Enum):
    """Data sources supported by theHarvester."""
    ANUBIS = "anubis"
    BAIDU = "baidu"
    BING = "bing"
    BINGAPI = "bingapi"
    CERTSPOTTER = "certspotter"
    CRTSH = "crtsh"
    DNSDUMPSTER = "dnsdumpster"
    DUCKDUCKGO = "duckduckgo"
    HACKERTARGET = "hackertarget"
    HUNTER = "hunter"
    OTXALIENVAULT = "otx"
    RAPIDDNS = "rapiddns"
    SECURITYTRAILS = "securityTrails"
    THREATMINER = "threatminer"
    URLSCAN = "urlscan"
    VIRUSTOTAL = "virustotal"
    YAHOO = "yahoo"


class HarvesterInput(BaseModel):
    """Input for theHarvester."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    domain: str = Field(
        ...,
        description="Target domain for OSINT collection (e.g., 'example.com')",
        min_length=3,
        max_length=253,
    )
    sources: Optional[List[HarvesterSource]] = Field(
        default=None,
        description=(
            "Data sources to query. Defaults to a broad set if not specified. "
            "Common choices: 'crtsh', 'duckduckgo', 'hackertarget', 'rapiddns', 'urlscan'"
        ),
    )
    limit: int = Field(
        default=500,
        description="Maximum number of results to retrieve per source",
        ge=10,
        le=5000,
    )
    start: int = Field(
        default=0,
        description="Result offset for pagination",
        ge=0,
    )
    dns_lookup: bool = Field(
        default=False,
        description="Perform DNS resolution on discovered hosts",
    )
    dns_brute: bool = Field(
        default=False,
        description="Perform DNS brute-force on the domain",
    )
    virtual_host: bool = Field(
        default=False,
        description="Verify discovered hosts via virtual host resolution",
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Timeout in seconds",
        ge=30,
        le=600,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if v.startswith(("http://", "https://")):
            v = v.split("//", 1)[1]
        v = v.split("/")[0]
        return v


@mcp.tool(
    name="harvest_osint",
    annotations={
        "title": "theHarvester — Email, Subdomain & IP OSINT",
        "readOnlyHint": True,  # Passive OSINT
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def harvest_osint(params: HarvesterInput) -> str:
    """Gather emails, subdomains, IPs, and names for a target domain using theHarvester.

    Queries public data sources (search engines, certificate transparency,
    DNS databases) for OSINT. This is primarily a passive tool, though
    dns_brute and dns_lookup options will generate DNS traffic.

    Args:
        params (HarvesterInput): Collection configuration.

    Returns:
        str: Discovered emails, hosts, and IPs (Markdown or JSON).
    """
    _check_binary("theHarvester")

    # Default to a broad, API-key-free source set if none specified
    sources = (
        ",".join(s.value for s in params.sources)
        if params.sources
        else "crtsh,duckduckgo,hackertarget,rapiddns,urlscan,anubis,certspotter,threatminer"
    )

    cmd = [
        "theHarvester",
        "-d", params.domain,
        "-b", sources,
        "-l", str(params.limit),
        "-S", str(params.start),
    ]

    if params.dns_lookup:
        cmd.append("-n")
    if params.dns_brute:
        cmd.append("-c")
    if params.virtual_host:
        cmd.append("-v")

    result = await _run_command(cmd, timeout=params.timeout)

    return _format_result(result, "theHarvester", params.response_format)


@mcp.tool(
    name="recon_theharvester",
    annotations={
        "title": "DEPRECATED: Use harvest_osint",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_theharvester(params: HarvesterInput) -> str:
    """Deprecated alias for harvest_osint."""
    return await harvest_osint(params)


# =========================================================================
# TOOL 8 — Shodan Host Lookup
# =========================================================================

class ShodanHostInput(BaseModel):
    """Input for Shodan host lookup."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: str = Field(
        ...,
        description="Target IP address to lookup (e.g., '8.8.8.8')",
        min_length=7,
        max_length=45,
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="lookup_shodan_host",
    annotations={
        "title": "Shodan Host Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def lookup_shodan_host(params: ShodanHostInput) -> str:
    """Look up a host on Shodan to get open ports, services, and vulnerabilities.

    Queries Shodan for detailed information about an IP address including
    open ports, running services, banners, and known vulnerabilities.

    Args:
        params (ShodanHostInput): IP address to lookup.

    Returns:
        str: Host information from Shodan (Markdown or JSON).
    """
    if not SHODAN_AVAILABLE:
        return "Error: Shodan integration requires 'shodan' package. Install with: pip install shodan"

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return "Error: SHODAN_API_KEY environment variable not set. Get a key from https://account.shodan.io/"

    try:
        api = shodan.Shodan(api_key)
        logger.info(f"Looking up host: {params.ip}")
        host = api.host(params.ip)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(host, indent=2)

        # Format as markdown
        lines = [f"## Shodan Host: {params.ip}\n"]
        lines.append(f"**Organization:** {host.get('org', 'N/A')}")
        lines.append(f"**ISP:** {host.get('isp', 'N/A')}")
        lines.append(f"**Location:** {host.get('city', 'N/A')}, {host.get('country_name', 'N/A')}")
        lines.append(f"**OS:** {host.get('os', 'N/A')}\n")

        if host.get('vulns'):
            lines.append(f"### 🚨 Vulnerabilities ({len(host['vulns'])})\n")
            for vuln in list(host['vulns'])[:10]:  # Limit to 10
                lines.append(f"- {vuln}")

        if host.get('ports'):
            lines.append(f"\n### 🔓 Open Ports ({len(host['ports'])})\n")
            lines.append(", ".join(str(p) for p in host['ports']))

        if host.get('data'):
            lines.append(f"\n### 📡 Services ({len(host['data'])})\n")
            for item in host['data'][:5]:  # Limit to 5
                port = item.get('port', 'N/A')
                transport = item.get('transport', 'N/A')
                product = item.get('product', item.get('_shodan', {}).get('module', 'N/A'))
                lines.append(f"\n**Port {port}/{transport}** - {product}")
                if item.get('version'):
                    lines.append(f"Version: {item['version']}")
                if item.get('data'):
                    banner = item['data'][:200].replace('\n', ' ')
                    lines.append(f"```\n{banner}...\n```")

        lines.append(f"\n_Last updated: {host.get('last_update', 'N/A')}_")
        return "\n".join(lines)

    except shodan.APIError as e:
        logger.error(f"Shodan API error: {e}")
        return f"Error: Shodan API error - {e}"
    except Exception as e:
        logger.error(f"Shodan lookup failed: {e}")
        return f"Error: {e}"


@mcp.tool(
    name="recon_shodan_host",
    annotations={
        "title": "DEPRECATED: Use lookup_shodan_host",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_shodan_host(params: ShodanHostInput) -> str:
    """Deprecated alias for lookup_shodan_host."""
    return await lookup_shodan_host(params)


# =========================================================================
# TOOL 9 — Shodan Search
# =========================================================================

class ShodanSearchInput(BaseModel):
    """Input for Shodan search."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query: str = Field(
        ...,
        description="Shodan search query (e.g., 'apache', 'port:22', 'org:\"Company Name\"')",
        min_length=1,
        max_length=500,
    )

    max_results: int = Field(
        default=10,
        description="Maximum number of results to return",
        ge=1,
        le=100,
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="search_shodan",
    annotations={
        "title": "Shodan Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def search_shodan(params: ShodanSearchInput) -> str:
    """Search Shodan for hosts matching a query.

    Searches Shodan's database for hosts matching specific criteria like
    products, ports, organizations, countries, etc.

    Args:
        params (ShodanSearchInput): Search query and options.

    Returns:
        str: Search results from Shodan (Markdown or JSON).
    """
    if not SHODAN_AVAILABLE:
        return "Error: Shodan integration requires 'shodan' package. Install with: pip install shodan"

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return "Error: SHODAN_API_KEY environment variable not set. Get a key from https://account.shodan.io/"

    try:
        api = shodan.Shodan(api_key)
        logger.info(f"Searching Shodan: {params.query}")
        results = api.search(params.query, limit=params.max_results)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "query": params.query,
                "total": results['total'],
                "matches": results['matches']
            }, indent=2)

        # Format as markdown
        lines = [f"## Shodan Search: `{params.query}`\n"]
        lines.append(f"**Total results:** {results['total']:,}\n")
        lines.append(f"**Showing:** {len(results['matches'])} results\n")

        for i, match in enumerate(results['matches'], 1):
            ip = match.get('ip_str', 'N/A')
            port = match.get('port', 'N/A')
            org = match.get('org', 'N/A')
            location = f"{match.get('location', {}).get('city', 'N/A')}, {match.get('location', {}).get('country_code', 'N/A')}"

            lines.append(f"\n### {i}. {ip}:{port}")
            lines.append(f"**Organization:** {org}")
            lines.append(f"**Location:** {location}")

            if match.get('product'):
                lines.append(f"**Product:** {match['product']}")
            if match.get('version'):
                lines.append(f"**Version:** {match['version']}")

            if match.get('data'):
                banner = match['data'][:150].replace('\n', ' ')
                lines.append(f"```\n{banner}...\n```")

        return "\n".join(lines)

    except shodan.APIError as e:
        logger.error(f"Shodan API error: {e}")
        return f"Error: Shodan API error - {e}"
    except Exception as e:
        logger.error(f"Shodan search failed: {e}")
        return f"Error: {e}"


@mcp.tool(
    name="recon_shodan_search",
    annotations={
        "title": "DEPRECATED: Use search_shodan",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_shodan_search(params: ShodanSearchInput) -> str:
    """Deprecated alias for search_shodan."""
    return await search_shodan(params)


# =========================================================================
# TOOL 10 — Shodan DNS Lookup
# =========================================================================

class ShodanDNSInput(BaseModel):
    """Input for Shodan DNS lookup."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    domain: str = Field(
        ...,
        description="Domain name to lookup (e.g., 'example.com')",
        min_length=3,
        max_length=253,
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="resolve_shodan_dns",
    annotations={
        "title": "Shodan DNS Lookup",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def resolve_shodan_dns(params: ShodanDNSInput) -> str:
    """Resolve domain to IP addresses using Shodan DNS.

    Uses Shodan's DNS service to resolve a domain name to its IP addresses.

    Args:
        params (ShodanDNSInput): Domain to lookup.

    Returns:
        str: DNS resolution results (Markdown or JSON).
    """
    if not SHODAN_AVAILABLE:
        return "Error: Shodan integration requires 'shodan' package. Install with: pip install shodan"

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return "Error: SHODAN_API_KEY environment variable not set. Get a key from https://account.shodan.io/"

    try:
        api = shodan.Shodan(api_key)
        logger.info(f"DNS lookup: {params.domain}")
        results = api.dns.resolve(params.domain)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "domain": params.domain,
                "ips": results if results else []
            }, indent=2)

        # Format as markdown
        lines = [f"## Shodan DNS: {params.domain}\n"]
        if results:
            lines.append("**IP Addresses:**\n")
            for ip in results:
                lines.append(f"- {ip}")
        else:
            lines.append("_No IP addresses found_")

        return "\n".join(lines)

    except shodan.APIError as e:
        logger.error(f"Shodan API error: {e}")
        return f"Error: Shodan API error - {e}"
    except Exception as e:
        logger.error(f"Shodan DNS lookup failed: {e}")
        return f"Error: {e}"


@mcp.tool(
    name="recon_shodan_dns",
    annotations={
        "title": "DEPRECATED: Use resolve_shodan_dns",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_shodan_dns(params: ShodanDNSInput) -> str:
    """Deprecated alias for resolve_shodan_dns."""
    return await resolve_shodan_dns(params)


# =========================================================================
# TOOL 11 — GitHub Code Search
# =========================================================================

class GitHubSearchInput(BaseModel):
    """Input for GitHub code search."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query: str = Field(
        ...,
        description="Search query (e.g., 'example.com password', 'org:company api_key')",
        min_length=1,
        max_length=500,
    )

    domain: Optional[str] = Field(
        default=None,
        description="Scope search to a specific domain (will search for domain mentions)",
        max_length=253,
    )

    search_type: str = Field(
        default="secrets",
        description="Search focus: 'secrets' (passwords/keys), 'code' (general), 'endpoints' (URLs/APIs)",
    )

    max_results: int = Field(
        default=20,
        description="Maximum number of results to return",
        ge=1,
        le=100,
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="search_github_secrets",
    annotations={
        "title": "GitHub Code Search",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def search_github_secrets(params: GitHubSearchInput) -> str:
    """Search GitHub for exposed secrets, credentials, and sensitive information.

    Searches GitHub's code, commits, and issues for mentions of domains, API keys,
    passwords, internal URLs, and other sensitive data that may have been accidentally
    committed.

    Args:
        params (GitHubSearchInput): Search query and options.

    Returns:
        str: GitHub search results with repositories, files, and code snippets.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        return "Error: GITHUB_TOKEN environment variable not set. Required for GitHub API access."

    # Build search query
    if params.domain:
        if params.search_type == "secrets":
            # Search for common secret patterns with domain
            search_queries = [
                f'"{params.domain}" password',
                f'"{params.domain}" api_key',
                f'"{params.domain}" secret',
                f'"{params.domain}" token',
                f'"{params.domain}" credentials',
            ]
        elif params.search_type == "endpoints":
            search_queries = [
                f'"{params.domain}" /api/',
                f'"{params.domain}" endpoint',
                f'"{params.domain}" graphql',
            ]
        else:
            search_queries = [f'"{params.domain}" {params.query}']
    else:
        search_queries = [params.query]

    all_results = []
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            for query in search_queries[:3]:  # Limit to 3 queries to avoid rate limits
                logger.info(f"Searching GitHub for: {query}")

                # Search code
                response = await client.get(
                    "https://api.github.com/search/code",
                    headers=headers,
                    params={"q": query, "per_page": min(params.max_results, 30)},
                )

                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("items", [])[:params.max_results]:
                        all_results.append({
                            "query": query,
                            "repository": item.get("repository", {}).get("full_name", "Unknown"),
                            "file": item.get("path", ""),
                            "url": item.get("html_url", ""),
                            "repo_url": item.get("repository", {}).get("html_url", ""),
                        })
                elif response.status_code == 403:
                    logger.warning("GitHub API rate limit reached")
                    break
                else:
                    logger.error(f"GitHub API error: {response.status_code}")

                # Small delay to avoid rate limits
                await asyncio.sleep(1)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "tool": "search_github_secrets",
                "domain": params.domain,
                "queries": search_queries,
                "total_results": len(all_results),
                "results": all_results
            }, indent=2)

        # Format as markdown
        lines = [f"## GitHub Code Search\n"]
        if params.domain:
            lines.append(f"**Domain:** {params.domain}")
        lines.append(f"**Search type:** {params.search_type}")
        lines.append(f"**Total results:** {len(all_results)}\n")

        if not all_results:
            lines.append("_No results found_")
        else:
            current_query = None
            for i, result in enumerate(all_results, 1):
                if result["query"] != current_query:
                    current_query = result["query"]
                    lines.append(f"\n### Query: `{current_query}`\n")

                lines.append(f"{i}. **{result['repository']}** - `{result['file']}`")
                lines.append(f"   🔗 [{result['url']}]({result['url']})")
                lines.append(f"   📦 Repository: [{result['repo_url']}]({result['repo_url']})\n")

        lines.append("\n> ⚠️ **Warning:** Review findings to confirm they are actual exposures and not false positives.")

        return "\n".join(lines)

    except httpx.TimeoutException:
        logger.error("GitHub API request timed out")
        return "Error: GitHub API request timed out"
    except Exception as e:
        logger.error(f"GitHub search failed: {e}")
        return f"Error: {e}"


@mcp.tool(
    name="recon_github_search",
    annotations={
        "title": "DEPRECATED: Use search_github_secrets",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_github_search(params: GitHubSearchInput) -> str:
    """Deprecated alias for search_github_secrets."""
    return await search_github_secrets(params)


# =========================================================================
# TOOL 12 — Wayback Machine / Archive.org
# =========================================================================

class WaybackInput(BaseModel):
    """Input for Wayback Machine lookups."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(
        ...,
        description="URL to look up in the Wayback Machine (e.g., 'example.com' or 'https://example.com/admin')",
        min_length=3,
        max_length=500,
    )

    limit: int = Field(
        default=10,
        description="Maximum number of snapshots to return",
        ge=1,
        le=100,
    )

    filter_status: Optional[str] = Field(
        default=None,
        description="Filter by HTTP status code (e.g., '200', '404', '301')",
    )

    year: Optional[int] = Field(
        default=None,
        description="Filter snapshots by year (e.g., 2020)",
        ge=1996,
        le=2026,
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="query_wayback",
    annotations={
        "title": "Wayback Machine History",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def query_wayback(params: WaybackInput) -> str:
    """Query the Wayback Machine for historical snapshots of a URL.

    Retrieves archived versions of web pages from Archive.org's Wayback Machine.
    Useful for finding old endpoints, deleted pages, exposed admin panels, or
    historical versions of websites.

    Args:
        params (WaybackInput): URL and filter options.

    Returns:
        str: Historical snapshots with dates and archive URLs.
    """
    # Normalize URL
    url = params.url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.info(f"Querying Wayback Machine for: {url}")

            # Use CDX Server API for better filtering
            cdx_params = {
                "url": url,
                "output": "json",
                "limit": params.limit,
                "fl": "timestamp,original,statuscode,mimetype,digest",
                "filter": "statuscode:200",  # Default to successful responses
                "collapse": "digest",  # Remove duplicates
            }

            if params.filter_status:
                cdx_params["filter"] = f"statuscode:{params.filter_status}"

            if params.year:
                # Filter by year using from/to parameters
                cdx_params["from"] = f"{params.year}0101"
                cdx_params["to"] = f"{params.year}1231"

            response = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params=cdx_params,
            )

            if response.status_code != 200:
                return f"Error: Wayback Machine API returned status {response.status_code}"

            data = response.json()

            # First row is headers, skip it
            if len(data) <= 1:
                return f"No archived snapshots found for {url}"

            snapshots = []
            for row in data[1:]:  # Skip header row
                timestamp, original, statuscode, mimetype, digest = row
                # Convert timestamp (YYYYMMDDhhmmss) to readable format
                year = timestamp[:4]
                month = timestamp[4:6]
                day = timestamp[6:8]
                time = f"{timestamp[8:10]}:{timestamp[10:12]}:{timestamp[12:14]}"

                archive_url = f"https://web.archive.org/web/{timestamp}/{original}"

                snapshots.append({
                    "date": f"{year}-{month}-{day}",
                    "time": time,
                    "timestamp": timestamp,
                    "status": statuscode,
                    "mimetype": mimetype,
                    "url": original,
                    "archive_url": archive_url,
                })

            if params.response_format == ResponseFormat.JSON:
                return json.dumps({
                    "tool": "query_wayback",
                    "url": url,
                    "total_snapshots": len(snapshots),
                    "snapshots": snapshots
                }, indent=2)

            # Format as markdown
            lines = [f"## Wayback Machine: {url}\n"]
            lines.append(f"**Total snapshots found:** {len(snapshots)}\n")

            if params.year:
                lines.append(f"**Filtered by year:** {params.year}\n")
            if params.filter_status:
                lines.append(f"**Filtered by status:** {params.filter_status}\n")

            for i, snapshot in enumerate(snapshots, 1):
                lines.append(f"\n### {i}. {snapshot['date']} at {snapshot['time']}")
                lines.append(f"**Status:** {snapshot['status']} | **Type:** {snapshot['mimetype']}")
                lines.append(f"**Archive URL:** {snapshot['archive_url']}")
                lines.append(f"**Original:** {snapshot['url']}")

            lines.append("\n> 💡 **Tip:** Use archive URLs to view historical versions of pages, find deleted content, or discover old endpoints.")

            return "\n".join(lines)

    except httpx.TimeoutException:
        logger.error("Wayback Machine API request timed out")
        return "Error: Wayback Machine API request timed out"
    except Exception as e:
        logger.error(f"Wayback Machine lookup failed: {e}")
        return f"Error: {e}"


@mcp.tool(
    name="recon_wayback",
    annotations={
        "title": "DEPRECATED: Use query_wayback",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_wayback(params: WaybackInput) -> str:
    """Deprecated alias for query_wayback."""
    return await query_wayback(params)


# =========================================================================
# TOOL 13 — TruffleHog Secret Scanner
# =========================================================================

class TruffleHogInput(BaseModel):
    """Input for TruffleHog secret scanning."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    target: str = Field(
        ...,
        description="Target to scan: GitHub org (org:company), GitHub repo URL, or local path",
        min_length=1,
        max_length=500,
    )

    scan_type: str = Field(
        default="github",
        description="Scan type: 'github' (repo/org), 'filesystem' (local path), 'git' (clone and scan)",
    )

    verify: bool = Field(
        default=True,
        description="Verify found secrets are still active (makes API calls to validate)",
    )

    include_detectors: Optional[str] = Field(
        default=None,
        description="Comma-separated list of detectors to include (e.g., 'aws,github,slack')",
        max_length=500,
    )

    exclude_detectors: Optional[str] = Field(
        default=None,
        description="Comma-separated list of detectors to exclude",
        max_length=500,
    )

    max_depth: int = Field(
        default=50,
        description="Maximum commit depth to scan (default 50, 0 for all)",
        ge=0,
        le=1000,
    )

    timeout: int = Field(
        default=600,
        description="Timeout in seconds (TruffleHog can be slow on large repos)",
        ge=60,
        le=3600,
    )

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="hunt_secrets",
    annotations={
        "title": "TruffleHog Secret Scanner",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,  # Verification makes API calls
        "openWorldHint": True,
    },
)
async def hunt_secrets(params: TruffleHogInput) -> str:
    """Scan for secrets and credentials using TruffleHog.

    TruffleHog scans git repositories, GitHub orgs, and filesystems for secrets
    using 200+ built-in detectors and entropy analysis. Can verify if found
    secrets are still active.

    Detects: AWS keys, API tokens, private keys, passwords, database credentials,
    OAuth tokens, and many more secret types.

    Args:
        params (TruffleHogInput): Target and scan configuration.

    Returns:
        str: Detected secrets with details (type, location, verification status).
    """
    _check_binary("trufflehog")

    cmd = ["trufflehog"]

    # Determine scan type and build command
    scan_type = params.scan_type.lower()
    target = params.target.strip()

    if scan_type == "github":
        # GitHub scanning
        cmd.append("github")

        # Check if it's an org or repo
        if target.startswith("org:"):
            org_name = target[4:]
            cmd.extend(["--org", org_name])
        elif target.startswith(("http://", "https://", "git@")):
            cmd.extend(["--repo", target])
        else:
            # Assume it's a repo in format owner/repo
            cmd.extend(["--repo", f"https://github.com/{target}"])

        # GitHub token if available
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token:
            cmd.extend(["--token", github_token])

    elif scan_type == "filesystem":
        cmd.append("filesystem")
        cmd.append(target)

    elif scan_type == "git":
        cmd.append("git")
        cmd.append(target)

    else:
        return f"Error: Invalid scan_type '{params.scan_type}'. Use 'github', 'filesystem', or 'git'."

    # Common options
    cmd.append("--json")  # JSON output for parsing

    if params.verify:
        cmd.append("--verify")

    if params.include_detectors:
        cmd.extend(["--include-detectors", params.include_detectors])

    if params.exclude_detectors:
        cmd.extend(["--exclude-detectors", params.exclude_detectors])

    if params.max_depth > 0:
        cmd.extend(["--max-depth", str(params.max_depth)])

    # Only scan, don't fail on findings
    cmd.append("--no-fail")

    logger.info(f"Running TruffleHog: {' '.join(cmd)}")

    result = await _run_command(cmd, timeout=params.timeout)

    # Parse JSON output
    findings = []
    if result["stdout"]:
        for line in result["stdout"].strip().split("\n"):
            if line.strip():
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue

    if params.response_format == ResponseFormat.JSON:
        return json.dumps({
            "tool": "hunt_secrets",
            "target": params.target,
            "scan_type": params.scan_type,
            "total_findings": len(findings),
            "verified": params.verify,
            "findings": findings
        }, indent=2)

    # Format as markdown
    lines = [f"## TruffleHog Secret Scan\n"]
    lines.append(f"**Target:** {params.target}")
    lines.append(f"**Scan type:** {params.scan_type}")
    lines.append(f"**Verification:** {'enabled' if params.verify else 'disabled'}")
    lines.append(f"**Total findings:** {len(findings)}\n")

    if not findings:
        lines.append("✅ **No secrets detected**")
    else:
        # Group by detector type
        by_detector = {}
        verified_count = 0

        for finding in findings:
            detector = finding.get("DetectorName", "Unknown")
            if detector not in by_detector:
                by_detector[detector] = []
            by_detector[detector].append(finding)

            if finding.get("Verified", False):
                verified_count += 1

        lines.append(f"🔴 **Verified secrets:** {verified_count}")
        lines.append(f"⚠️ **Unverified findings:** {len(findings) - verified_count}\n")

        # Display findings by detector
        for detector, detector_findings in sorted(by_detector.items()):
            lines.append(f"\n### {detector} ({len(detector_findings)} found)\n")

            for i, finding in enumerate(detector_findings[:5], 1):  # Limit to 5 per detector
                verified = finding.get("Verified", False)
                status = "🔴 VERIFIED" if verified else "⚠️ Unverified"

                lines.append(f"{i}. **{status}**")

                # Source info
                source = finding.get("SourceMetadata", {})
                if scan_type == "github":
                    repo = source.get("Data", {}).get("Github", {}).get("repository", "")
                    file_path = source.get("Data", {}).get("Github", {}).get("file", "")
                    commit = source.get("Data", {}).get("Github", {}).get("commit", "")[:8]

                    if repo and file_path:
                        lines.append(f"   **Repo:** {repo}")
                        lines.append(f"   **File:** {file_path}")
                        lines.append(f"   **Commit:** {commit}")
                else:
                    # Filesystem
                    file_path = source.get("Data", {}).get("Filesystem", {}).get("file", "")
                    if file_path:
                        lines.append(f"   **File:** {file_path}")

                # Raw secret (truncated)
                raw = finding.get("Raw", "")
                if raw:
                    display_secret = raw[:30] + "..." if len(raw) > 30 else raw
                    lines.append(f"   **Secret:** `{display_secret}`")

                lines.append("")

            if len(detector_findings) > 5:
                lines.append(f"   _...and {len(detector_findings) - 5} more_\n")

        lines.append("\n> 🚨 **CRITICAL:** If verified secrets are found, rotate them immediately!")

    if result["stderr"]:
        lines.append(f"\n### Warnings/Errors\n```\n{result['stderr'][:500]}\n```")

    return "\n".join(lines)


@mcp.tool(
    name="recon_trufflehog",
    annotations={
        "title": "DEPRECATED: Use hunt_secrets",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def recon_trufflehog(params: TruffleHogInput) -> str:
    """Deprecated alias for hunt_secrets."""
    return await hunt_secrets(params)


# =========================================================================
# TOOL 14 — WebScope (web content discovery & analysis)
# =========================================================================

class WebScopeFlow(str, Enum):
    """WebScope discovery flow levels."""
    QUICK = "quick"
    IN_DEPTH = "in-depth"
    INTENSE = "intense"


class WebScopeInput(BaseModel):
    """Input for WebScope web content analysis."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    target: str = Field(
        ...,
        description="Target URL to analyze (e.g., 'https://example.com')",
        min_length=5,
        max_length=500,
    )
    flow: WebScopeFlow = Field(
        default=WebScopeFlow.QUICK,
        description=(
            "Discovery flow: 'quick' (robots/sitemap/basic ~30 reqs), "
            "'in-depth' (+urlfinder/katana/jsluice ~100 reqs), "
            "'intense' (+large wordlists/deep crawl/patterns ~500+ reqs)"
        ),
    )
    modules: Optional[str] = Field(
        default=None,
        description=(
            "Comma-separated discovery modules to enable. "
            "Options: http, robots, sitemap, paths, javascript, "
            "advanced-javascript, patterns. Default depends on flow."
        ),
        max_length=300,
    )
    depth: int = Field(
        default=2,
        description="Maximum crawl depth",
        ge=1,
        le=5,
    )
    workers: int = Field(
        default=20,
        description="Number of concurrent workers",
        ge=1,
        le=100,
    )
    rate_limit: int = Field(
        default=20,
        description="Max requests per second",
        ge=1,
        le=200,
    )
    max_requests: Optional[int] = Field(
        default=None,
        description="Hard cap on total requests (useful for intense flow)",
        ge=10,
        le=5000,
    )
    wordlist: Optional[str] = Field(
        default=None,
        description="Custom wordlist path for path bruteforcing",
        max_length=500,
    )
    output_format: str = Field(
        default="jsonl",
        description="Output format: 'jsonl' (streaming JSON Lines) or 'json' (standard JSON)",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output",
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Overall execution timeout in seconds",
        ge=30,
        le=1200,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="MCP output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="recon_webscope",
    annotations={
        "title": "WebScope — Web Content Discovery & Analysis",
        "readOnlyHint": False,  # Sends HTTP requests
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_webscope(params: WebScopeInput) -> str:
    """Discover web content, endpoints, secrets, and technologies using WebScope.

    WebScope performs static web content analysis including robots.txt/sitemap
    parsing, path bruteforcing with smart variations, JavaScript analysis
    (jsluice), GraphQL/WebSocket discovery, and pattern-based secret detection.

    Three progressive flows control depth:
    - quick: robots.txt + sitemap + basic paths (~30 requests)
    - in-depth: + urlfinder + katana crawling + jsluice (~100 requests)
    - intense: + large wordlists + deep crawling + patterns (~500+ requests)

    ⚠️ ACTIVE tool — sends HTTP requests. Only use on authorized targets.

    Args:
        params (WebScopeInput): Target and analysis configuration.

    Returns:
        str: Discovered paths, endpoints, secrets, and technologies.
    """
    _check_binary("webscope")

    cmd = ["webscope", "-target", params.target]
    cmd.extend(["-flow", params.flow.value])
    cmd.extend(["-w", str(params.workers)])
    cmd.extend(["-r", str(params.rate_limit)])
    cmd.extend(["-of", params.output_format])

    if params.modules:
        cmd.extend(["-m", params.modules])
    if params.depth != 2:
        cmd.extend(["-depth", str(params.depth)])
    if params.max_requests:
        cmd.extend(["-max-requests", str(params.max_requests)])
    if params.wordlist:
        wordlist_path = _get_wordlist_path(params.wordlist)
        if wordlist_path:
            cmd.extend(["-wordlist", wordlist_path])
        else:
            return f"Error: Wordlist not found: {params.wordlist}"
    if params.verbose:
        cmd.append("-v")

    result = await _run_command(cmd, timeout=params.timeout)

    # Parse JSONL output for structured summary
    if result["stdout"] and params.output_format == "jsonl":
        discoveries = []
        summary = {}
        for line in result["stdout"].strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "summary":
                    summary = obj.get("statistics", {})
                else:
                    discoveries.append(obj)
            except (json.JSONDecodeError, ValueError):
                continue

        if params.response_format == ResponseFormat.JSON:
            output = {
                "tool": "webscope",
                "target": params.target,
                "flow": params.flow.value,
                "statistics": summary,
                "discoveries": discoveries[:50],  # Cap at 50 items
            }
            if len(discoveries) > 50:
                output["truncated"] = f"{len(discoveries) - 50} more items omitted"
            raw = json.dumps(output, indent=2)
            if len(raw) > MAX_OUTPUT_CHARS:
                return _smart_summarize_json(result["stdout"])
            return raw

        # Markdown summary
        lines = [f"## WebScope — {params.target}\n"]
        lines.append(f"**Flow:** {params.flow.value}")
        if summary:
            lines.append(f"**Paths found:** {summary.get('total_paths', 'N/A')}")
            lines.append(f"**Endpoints:** {summary.get('total_endpoints', 'N/A')}")
            lines.append(f"**Secrets:** {summary.get('total_secrets', 'N/A')}")
            lines.append(f"**Forms:** {summary.get('total_forms', 'N/A')}")

        # Show compact discovery summary
        paths_shown = 0
        for disc in discoveries[:20]:
            d = disc.get("discovery", disc)
            domain = d.get("domain", "")
            paths = d.get("paths", [])
            endpoints = d.get("endpoints", [])
            secrets = d.get("secrets", [])

            if paths:
                lines.append(f"\n### Paths ({domain or params.target})\n")
                for p in paths[:30]:
                    url = p.get("url", p) if isinstance(p, dict) else str(p)
                    status = p.get("status_code", "") if isinstance(p, dict) else ""
                    status_str = f" [{status}]" if status else ""
                    lines.append(f"- {url}{status_str}")
                    paths_shown += 1
                if len(paths) > 30:
                    lines.append(f"_... {len(paths) - 30} more paths_")

            if endpoints:
                lines.append(f"\n### Endpoints\n")
                for ep in endpoints[:20]:
                    lines.append(f"- {ep.get('url', ep) if isinstance(ep, dict) else ep}")
                if len(endpoints) > 20:
                    lines.append(f"_... {len(endpoints) - 20} more endpoints_")

            if secrets:
                lines.append(f"\n### 🚨 Secrets Detected\n")
                for s in secrets[:10]:
                    stype = s.get("type", "unknown") if isinstance(s, dict) else "unknown"
                    sval = s.get("value", str(s))[:60] if isinstance(s, dict) else str(s)[:60]
                    lines.append(f"- **{stype}**: `{sval}...`")

        if not discoveries and not summary:
            # Fall back to raw output
            lines.append(f"\n```\n{_truncate_output(result['stdout'])}\n```")

        return "\n".join(lines)

    # Fallback for non-JSONL or empty
    return _format_result(result, "WebScope", params.response_format)


# =========================================================================
# TOOL 15 — SubScope (advanced subdomain enumeration)
# =========================================================================

class SubScopeProfile(str, Enum):
    """SubScope rate limit profiles."""
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class SubScopeOutputFormat(str, Enum):
    """SubScope output formats."""
    JSON = "json"
    CSV = "csv"
    MASSDNS = "massdns"
    DNSX = "dnsx"
    AQUATONE = "aquatone"
    EYEWITNESS = "eyewitness"


class SubScopeInput(BaseModel):
    """Input for SubScope advanced subdomain enumeration."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    domain: str = Field(
        ...,
        description="Target domain for subdomain enumeration (e.g., 'example.com')",
        min_length=3,
        max_length=253,
    )
    all_phases: bool = Field(
        default=False,
        description="Enable ALL enumeration phases (passive, zone transfer, http, brute, geo, rdns, CT, persist)",
    )

    # Modular feature selection
    passive: bool = Field(
        default=False,
        description="Enable passive enumeration via subfinder",
    )
    zone_transfer: bool = Field(
        default=False,
        description="Attempt DNS zone transfers (AXFR)",
    )
    http_analysis: bool = Field(
        default=False,
        description="HTTP/HTTPS analysis via httpx (headers, SSL, redirects)",
    )
    brute: bool = Field(
        default=False,
        description="DNS brute force via alterx/shuffledns",
    )
    geo_dns: bool = Field(
        default=False,
        description="Geographic DNS analysis (multi-region queries)",
    )
    rdns: bool = Field(
        default=False,
        description="Reverse DNS lookups",
    )
    ct_logs: bool = Field(
        default=False,
        description="Certificate transparency log queries",
    )
    persist: bool = Field(
        default=False,
        description="Enable domain history tracking to find new domains across scans",
    )

    # Output control
    output_format: SubScopeOutputFormat = Field(
        default=SubScopeOutputFormat.JSON,
        description="Output format: json, csv, massdns, dnsx, aquatone, eyewitness",
    )
    profile: SubScopeProfile = Field(
        default=SubScopeProfile.NORMAL,
        description="Rate limit profile: stealth (5 rps), normal (20 rps), aggressive (100 rps)",
    )
    input_domains: Optional[str] = Field(
        default=None,
        description="Newline-separated list of additional domains to include (piped as file)",
        max_length=50000,
    )
    merge_input: bool = Field(
        default=False,
        description="Merge input domains with discovered domains (requires input_domains)",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output",
    )
    progress: bool = Field(
        default=False,
        description="Show progress bars",
    )

    # ProxyHawk integration
    proxyhawk_url: Optional[str] = Field(
        default=None,
        description="ProxyHawk server URL for enhanced geographic DNS (e.g., 'http://localhost:8080')",
        max_length=500,
    )
    proxyhawk_regions: Optional[str] = Field(
        default=None,
        description="Comma-separated ProxyHawk regions (e.g., 'us-east,us-west,eu-west')",
        max_length=300,
    )

    timeout: int = Field(
        default=600,
        description="Timeout in seconds (subscope can be slow for full scans)",
        ge=30,
        le=3600,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="MCP output format: 'markdown' or 'json'",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if v.startswith(("http://", "https://")):
            v = v.split("//", 1)[1]
        v = v.split("/")[0]
        return v


@mcp.tool(
    name="recon_subscope",
    annotations={
        "title": "SubScope — Advanced Subdomain Enumeration",
        "readOnlyHint": False,  # Can do active probing (http, brute, zone)
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_subscope(params: SubScopeInput) -> str:
    """Advanced subdomain enumeration combining multiple discovery techniques.

    SubScope wraps subfinder, httpx, shuffledns, and alterx into a single
    optimized pipeline with intelligent wildcard filtering, cloud service
    detection, geographic DNS analysis, and domain persistence tracking.

    Default pipeline: passive + zone-transfer + http + rdns.
    Use -a/--all for complete analysis including brute-force and geo-DNS.

    Features: multi-source discovery, CNAME/SOA cloud detection, stealth
    profiles, multiple output formats for tool chaining.

    Args:
        params (SubScopeInput): Enumeration configuration.

    Returns:
        str: Discovered subdomains with DNS records, cloud services, and metadata.
    """
    _check_binary("subscope")

    cmd = ["subscope", "-d", params.domain]

    # Output to stdout as JSON for parsing
    cmd.extend(["-o", "-"])
    cmd.extend(["-f", params.output_format.value])
    cmd.extend(["--profile", params.profile.value])

    if params.all_phases:
        cmd.append("-a")
    else:
        # Modular feature flags
        if params.passive:
            cmd.append("-p")
        if params.zone_transfer:
            cmd.append("-z")
        if params.http_analysis:
            cmd.append("-h")
        if params.brute:
            cmd.append("-b")
        if params.geo_dns:
            cmd.append("-g")
        if params.rdns:
            cmd.append("-r")
        if params.ct_logs:
            cmd.append("--ct")
        if params.persist:
            cmd.append("--persist")

    if params.verbose:
        cmd.append("-v")
    if params.progress:
        cmd.append("--progress")

    # ProxyHawk integration
    if params.proxyhawk_url:
        cmd.extend(["--proxyhawk-url", params.proxyhawk_url])
    if params.proxyhawk_regions:
        cmd.extend(["--proxyhawk-regions", params.proxyhawk_regions])

    # Handle input domains via temp file if provided
    stdin_data = None
    input_file = None
    if params.input_domains:
        import tempfile
        input_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="subscope_input_"
        )
        input_file.write(params.input_domains)
        input_file.close()
        cmd.extend(["-i", input_file.name])
        if params.merge_input:
            cmd.append("-m")

    try:
        result = await _run_command(cmd, timeout=params.timeout)
    finally:
        # Clean up temp file
        if input_file:
            try:
                os.unlink(input_file.name)
            except OSError:
                pass

    # Parse JSON output for structured summary
    if result["stdout"] and params.output_format == SubScopeOutputFormat.JSON:
        try:
            data = json.loads(result["stdout"])
        except (json.JSONDecodeError, ValueError):
            data = None

        if data and params.response_format == ResponseFormat.JSON:
            # Trim large sections to prevent overflow
            resolved = data.get("resolved_domains", [])
            discovered = data.get("discovered_domains", [])
            failed = data.get("failed_generated", [])
            output = {
                "tool": "subscope",
                "domain": params.domain,
                "metadata": data.get("metadata", {}),
                "statistics": data.get("statistics", {}),
                "resolved_domains": resolved[:100],
                "discovered_domains": discovered[:50],
            }
            if len(resolved) > 100:
                output["resolved_truncated"] = f"{len(resolved) - 100} more omitted"
            if len(discovered) > 50:
                output["discovered_truncated"] = f"{len(discovered) - 50} more omitted"
            output["failed_generated_count"] = len(failed)
            raw = json.dumps(output, indent=2)
            if len(raw) > MAX_OUTPUT_CHARS:
                # Ultra-compact: just domain list + stats
                compact = {
                    "tool": "subscope",
                    "domain": params.domain,
                    "statistics": data.get("statistics", {}),
                    "resolved_domain_names": [d.get("domain", "") for d in resolved[:200]],
                    "total_resolved": len(resolved),
                    "total_discovered": len(discovered),
                    "total_failed": len(failed),
                }
                return json.dumps(compact, indent=2)
            return raw

        if data and params.response_format == ResponseFormat.MARKDOWN:
            stats = data.get("statistics", {})
            resolved = data.get("resolved_domains", [])
            discovered = data.get("discovered_domains", [])

            lines = [f"## SubScope — {params.domain}\n"]
            lines.append(f"**Profile:** {params.profile.value}")
            if stats:
                lines.append(f"**Resolved:** {stats.get('domains_resolved', len(resolved))}")
                lines.append(f"**Discovered:** {stats.get('domains_discovered', len(discovered))}")
                lines.append(f"**Execution time:** {stats.get('execution_time', 'N/A')}")
                sources = stats.get("sources", [])
                if sources:
                    lines.append(f"**Sources:** {', '.join(sources)}")

            # Show resolved domains (compact table)
            if resolved:
                lines.append(f"\n### Resolved Domains ({len(resolved)} total)\n")
                lines.append("| Domain | IP | Cloud | Source |")
                lines.append("|--------|-----|-------|--------|")
                for d in resolved[:50]:
                    domain = d.get("domain", "")
                    ip = d.get("dns_records", {}).get("A", "N/A")
                    cloud = d.get("dns_records", {}).get("CLOUD_SERVICE", "")
                    source = d.get("source", "")
                    lines.append(f"| {domain} | {ip} | {cloud} | {source} |")
                if len(resolved) > 50:
                    lines.append(f"\n_... {len(resolved) - 50} more resolved domains_")

            # Show discovered (unresolved) domains
            if discovered:
                lines.append(f"\n### Discovered (unresolved) — {len(discovered)} total\n")
                for d in discovered[:20]:
                    lines.append(f"- {d.get('domain', d)}")
                if len(discovered) > 20:
                    lines.append(f"_... {len(discovered) - 20} more_")

            return "\n".join(lines)

    # Fallback for non-JSON formats or parse failure
    return _format_result(result, "SubScope", params.response_format)


# =========================================================================
# TOOL 16 — nmap (network/port scanning)
# =========================================================================

class NmapInput(BaseModel):
    """Input for nmap network scanning."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    target: str = Field(
        ...,
        description=(
            "Target specification: IP, hostname, CIDR range, or comma-separated list "
            "(e.g., '192.168.1.1', 'example.com', '10.0.0.0/24', '192.168.1.1,192.168.1.2')"
        ),
        min_length=1,
        max_length=1000,
    )
    ports: Optional[str] = Field(
        default=None,
        description=(
            "Port specification: single (80), range (1-1024), list (22,80,443), "
            "or special: 'top100', 'top1000'. Default: nmap's default 1000 ports."
        ),
        max_length=500,
    )
    scan_type: str = Field(
        default="service",
        description=(
            "Scan type: 'quick' (top 100 ports, fast), "
            "'service' (version detection -sV, default), "
            "'os' (OS + version detection -O -sV, may require root), "
            "'stealth' (SYN scan -sS, requires root), "
            "'udp' (UDP scan -sU, slow, requires root), "
            "'scripts' (default NSE scripts -sC -sV), "
            "'vuln' (vulnerability scripts --script vuln), "
            "'ping' (host discovery only -sn)"
        ),
    )
    timing: int = Field(
        default=3,
        description="Timing template 0-5: paranoid(0), sneaky(1), polite(2), normal(3), aggressive(4), insane(5)",
        ge=0,
        le=5,
    )
    no_ping: bool = Field(
        default=False,
        description="Skip host discovery, treat all hosts as online (-Pn). Useful for firewalled hosts.",
    )
    no_dns: bool = Field(
        default=False,
        description="Disable DNS resolution (-n) for faster scans",
    )
    extra_args: Optional[str] = Field(
        default=None,
        description="Additional nmap arguments to append verbatim (e.g., '--script http-enum --min-rate 1000')",
        max_length=500,
    )
    timeout: int = Field(
        default=600,
        description="Overall execution timeout in seconds",
        ge=30,
        le=3600,
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="recon_nmap",
    annotations={
        "title": "nmap — Network & Port Scanner",
        "readOnlyHint": False,  # Sends packets to target
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def recon_nmap(params: NmapInput) -> str:
    """Scan networks and hosts for open ports, services, and vulnerabilities using nmap.

    Supports multiple scan types from quick port checks to full vulnerability
    assessment. Some scan types (SYN, UDP, OS detection) require root/sudo.

    ⚠️ ACTIVE scanning tool — sends network packets to target.
    Only use against targets you have explicit authorization to test.

    Args:
        params (NmapInput): Target, ports, and scan configuration.

    Returns:
        str: Discovered hosts, ports, services, and script output.
    """
    _check_binary("nmap")

    cmd = ["nmap"]

    # Scan type presets
    scan_type = params.scan_type.lower().strip()
    if scan_type == "quick":
        cmd.extend(["-F", "-sV", "--version-light"])
    elif scan_type == "service":
        cmd.append("-sV")
    elif scan_type == "os":
        cmd.extend(["-O", "-sV"])
    elif scan_type == "stealth":
        cmd.append("-sS")
    elif scan_type == "udp":
        cmd.append("-sU")
    elif scan_type == "scripts":
        cmd.extend(["-sC", "-sV"])
    elif scan_type == "vuln":
        cmd.extend(["-sV", "--script", "vuln"])
    elif scan_type == "ping":
        cmd.append("-sn")
    else:
        return f"Error: Unknown scan_type '{scan_type}'. Use: quick, service, os, stealth, udp, scripts, vuln, ping"

    # Timing
    cmd.append(f"-T{params.timing}")

    # Ports
    if params.ports:
        p = params.ports.strip().lower()
        if p == "top100":
            cmd.append("-F")  # Fast scan = top 100
        elif p == "top1000":
            pass  # nmap default
        else:
            cmd.extend(["-p", params.ports])

    # Options
    if params.no_ping:
        cmd.append("-Pn")
    if params.no_dns:
        cmd.append("-n")

    # Extra args (split by spaces, respecting simple quoting)
    if params.extra_args:
        import shlex
        try:
            cmd.extend(shlex.split(params.extra_args))
        except ValueError:
            cmd.extend(params.extra_args.split())

    # Suppress runtime interaction, add XML output for parsing
    cmd.append("--noninteractive")

    # Target last
    cmd.append(params.target)

    result = await _run_command(cmd, timeout=params.timeout)

    # nmap outputs to stdout in normal format — parse key sections
    if result["stdout"] and params.response_format == ResponseFormat.MARKDOWN:
        raw = result["stdout"]
        lines = ["## nmap Scan Results\n"]
        lines.append(f"**Target:** {params.target}")
        lines.append(f"**Scan type:** {params.scan_type}")
        if params.ports:
            lines.append(f"**Ports:** {params.ports}")
        lines.append(f"**Timing:** T{params.timing}\n")

        if result["timed_out"]:
            lines.append("> ⚠️ **Scan timed out.** Partial results below.\n")
        if result["returncode"] != 0 and not result["timed_out"]:
            lines.append(f"> ⚠️ Exit code **{result['returncode']}**\n")

        # Truncate the raw nmap output
        truncated = _truncate_output(raw)
        lines.append(f"```\n{truncated}\n```")

        if result["stderr"].strip():
            stderr_trunc = _truncate_output(result["stderr"], max_lines=20, max_chars=1500)
            lines.append(f"\n### Stderr\n```\n{stderr_trunc}\n```")

        return "\n".join(lines)

    return _format_result(result, "nmap", params.response_format)


# =========================================================================
# UTILITY TOOL — List available tools and check binary status
# =========================================================================

class StatusInput(BaseModel):
    """Input for the status check tool."""
    model_config = ConfigDict(extra="forbid")

    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' or 'json'",
    )


@mcp.tool(
    name="check_tool_status",
    annotations={
        "title": "FieldKit MCP — Status & Dependency Check",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def check_tool_status(params: StatusInput) -> str:
    """Check the availability of all required reconnaissance binaries.

    Reports which tools are installed and on PATH. Use this before
    running scans to verify the environment is set up correctly.

    Args:
        params (StatusInput): Format options.

    Returns:
        str: Status report of all tool dependencies.
    """
    binaries = {
        "subfinder": "Subdomain enumeration",
        "nuclei": "Vulnerability scanning",
        "dnsx": "DNS resolution & enumeration",
        "httpx": "HTTP probing & tech detection",
        "katana": "Web crawling / spidering",
        "theHarvester": "Email, subdomain & IP OSINT",
        "trufflehog": "Secret & credential scanner",
        "webscope": "Web content discovery & analysis",
        "subscope": "Advanced subdomain enumeration",
        "nmap": "Network & port scanner",
    }

    statuses = {}
    for binary, desc in binaries.items():
        path = shutil.which(binary)
        statuses[binary] = {
            "description": desc,
            "installed": path is not None,
            "path": path or "NOT FOUND",
        }

    # Check for Python integrations
    python_integrations = {
        "duckduckgo-search": {
            "installed": DUCKDUCKGO_AVAILABLE,
            "description": "DuckDuckGo search (for dork_search, default engine)",
        },
        "googlesearch-python": {
            "installed": GOOGLE_SEARCH_AVAILABLE,
            "description": "Google search execution (for dork_search)",
        },
        "shodan": {
            "installed": SHODAN_AVAILABLE,
            "description": "Shodan API integration (for lookup/search/resolve shodan tools)",
        },
    }

    # Check for useful env vars
    env_vars = {
        "SHODAN_API_KEY": bool(os.environ.get("SHODAN_API_KEY")),
        "VIRUSTOTAL_API_KEY": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        "CENSYS_API_ID": bool(os.environ.get("CENSYS_API_ID")),
        "CHAOS_API_KEY": bool(os.environ.get("CHAOS_API_KEY")),
        "GITHUB_TOKEN": bool(os.environ.get("GITHUB_TOKEN")),
    }

    if params.response_format == ResponseFormat.JSON:
        return json.dumps({
            "tools": statuses,
            "python_integrations": python_integrations,
            "api_keys": env_vars
        }, indent=2)

    lines = ["## FieldKit MCP — Environment Status\n", "### Tool Binaries\n"]
    for name, info in statuses.items():
        icon = "✅" if info["installed"] else "❌"
        lines.append(f"- {icon} **{name}** — {info['description']} (`{info['path']}`)")

    lines.append("\n### Python Integrations\n")
    for name, info in python_integrations.items():
        icon = "✅" if info["installed"] else "❌"
        lines.append(f"- {icon} **{name}** — {info['description']}")

    lines.append("\n### API Keys (environment variables)\n")
    for var, present in env_vars.items():
        icon = "🔑" if present else "⬜"
        lines.append(f"- {icon} `{var}`: {'configured' if present else 'not set'}")

    lines.append(
        "\n> API keys are optional but significantly improve results for "
        "subfinder, nuclei, theHarvester, and Shodan tools. "
        "SHODAN_API_KEY is required for Shodan tools."
    )
    return "\n".join(lines)


@mcp.tool(
    name="recon_status",
    annotations={
        "title": "DEPRECATED: Use check_tool_status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def recon_status(params: StatusInput) -> str:
    """Deprecated alias for check_tool_status."""
    return await check_tool_status(params)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="FieldKit MCP Server")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="HTTP listen port (ignored if MCP_TRANSPORT=stdio)")
    parser.add_argument("--stdio", action="store_true", help="Use stdio transport (for Claude Desktop)")
    args = parser.parse_args()

    # Determine transport mode
    if args.stdio or os.environ.get("MCP_TRANSPORT", "").lower() == "stdio":
        logger.info("Starting fieldkit-mcp in stdio mode")
        mcp.run(transport="stdio")
    else:
        logger.info("Starting fieldkit-mcp on port %d (streamable HTTP)", args.port)
        mcp.run(transport="streamable-http")
