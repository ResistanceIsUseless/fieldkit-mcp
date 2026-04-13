#!/usr/bin/env python3
"""Web-surface MCP tools for phased merge rollout."""

import json
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, ConfigDict, Field

from cache import get_cached, list_cached, upsert_response


class ResponseFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON = "json"


class WebSearchInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query: str = Field(..., description="Search query")
    max_results: int = Field(default=10, ge=1, le=50)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class WebFetchInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(..., description="Target URL")
    method: str = Field(default="GET", description="HTTP method")
    headers_json: Optional[str] = Field(default=None, description="Optional request headers as JSON object string")
    body: Optional[str] = Field(default=None, description="Optional request body")
    follow_redirects: bool = Field(default=True, description="Follow redirects")
    timeout: int = Field(default=60, ge=5, le=600)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class WebRenderInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(..., description="Target URL")
    wait_until: str = Field(default="networkidle", description="Playwright wait state: load|domcontentloaded|networkidle")
    actions_json: Optional[str] = Field(
        default=None,
        description=(
            "Optional JSON array of actions to run after page load. "
            "Actions: click {selector}, type {selector,text}, scroll {x,y}, wait {ms}."
        ),
    )
    timeout: int = Field(default=90, ge=5, le=900)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class WebScreenshotInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(..., description="Target URL")
    full_page: bool = Field(default=True, description="Capture full page")
    viewport_width: int = Field(default=1440, ge=320, le=3840)
    viewport_height: int = Field(default=900, ge=240, le=2160)
    output_path: Optional[str] = Field(default=None, description="Optional output path for PNG")
    wait_until: str = Field(default="networkidle", description="Playwright wait state: load|domcontentloaded|networkidle")
    timeout: int = Field(default=90, ge=5, le=900)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class WebExtractInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(..., description="Target URL")
    mode: str = Field(default="readability", description="Extraction mode: readability|css|xpath")
    selector: Optional[str] = Field(default=None, description="CSS selector or XPath expression")
    prefer_cache: bool = Field(default=True, description="Try cached content before network fetch")
    cache_method: str = Field(default="RENDER", description="Cache method to use first: RENDER or GET")
    max_chars: int = Field(default=12000, ge=500, le=100000)
    timeout: int = Field(default=60, ge=5, le=600)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class FingerprintTechInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(..., description="Target URL")
    prefer_cache: bool = Field(default=True, description="Try cached content before network fetch")
    timeout: int = Field(default=60, ge=5, le=600)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


class QueryCacheInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: Optional[str] = Field(default=None, description="Optional URL for exact cache lookup")
    method: str = Field(default="GET", description="HTTP method for URL lookup")
    limit: int = Field(default=25, ge=1, le=200)
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)


def register_web_tools(mcp) -> None:
    """Register web-surface tools as phase stubs."""

    @mcp.tool(
        name="web_search",
        annotations={"title": "Web Search", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )
    async def web_search(params: WebSearchInput) -> str:
        try:
            from duckduckgo_search import DDGS
        except Exception:
            return "Error: duckduckgo-search is not installed."

        try:
            rows = []
            with DDGS() as ddgs:
                for item in ddgs.text(params.query, max_results=params.max_results):
                    rows.append(
                        {
                            "url": item.get("href", item.get("link", "")),
                            "title": item.get("title", ""),
                            "snippet": item.get("body", item.get("snippet", "")),
                        }
                    )
        except Exception as exc:
            return f"Error: web_search failed: {exc}"

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(
                {
                    "tool": "web_search",
                    "query": params.query,
                    "results": rows,
                },
                indent=2,
            )

        lines = ["## Web Search\n"]
        lines.append(f"**Query:** `{params.query}`")
        lines.append(f"**Results:** {len(rows)}\n")
        if not rows:
            lines.append("_No results found._")
        else:
            for i, row in enumerate(rows, 1):
                lines.append(f"{i}. **{row['title'] or 'Untitled'}**")
                lines.append(f"   {row['url']}")
                if row["snippet"]:
                    lines.append(f"   _{row['snippet'][:220]}_")
        return "\n".join(lines)

    @mcp.tool(
        name="web_fetch",
        annotations={"title": "Web Fetch", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )
    async def web_fetch(params: WebFetchInput) -> str:
        method = params.method.strip().upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            return f"Error: Unsupported method '{params.method}'."

        req_headers: Dict[str, str] = {}
        if params.headers_json:
            try:
                parsed = json.loads(params.headers_json)
            except json.JSONDecodeError as exc:
                return f"Error: headers_json is not valid JSON: {exc}"
            if not isinstance(parsed, dict):
                return "Error: headers_json must be a JSON object."
            req_headers = {str(k): str(v) for k, v in parsed.items()}

        try:
            async with httpx.AsyncClient(follow_redirects=params.follow_redirects, timeout=params.timeout) as client:
                resp = await client.request(
                    method=method,
                    url=params.url,
                    headers=req_headers,
                    content=params.body.encode() if params.body is not None else None,
                )
        except Exception as exc:
            return f"Error: web_fetch failed: {exc}"

        response_headers = dict(resp.headers)
        response_body = resp.content
        upsert_response(
            url=str(resp.url),
            method=method,
            status=resp.status_code,
            headers=response_headers,
            body=response_body,
        )

        body_text = response_body.decode("utf-8", errors="replace")
        body_text_preview = body_text[:8000]
        truncated = len(body_text) > len(body_text_preview)

        if params.response_format == ResponseFormat.JSON:
            payload: Dict[str, Any] = {
                "tool": "web_fetch",
                "url": str(resp.url),
                "method": method,
                "status": resp.status_code,
                "headers": response_headers,
                "body": body_text_preview,
                "body_bytes": len(response_body),
                "truncated": truncated,
                "robots": "ignored",
            }
            return json.dumps(payload, indent=2)

        lines = ["## Web Fetch\n"]
        lines.append(f"**URL:** `{resp.url}`")
        lines.append(f"**Method:** `{method}`")
        lines.append(f"**Status:** `{resp.status_code}`")
        lines.append("**Robots:** ignored\n")
        lines.append("### Headers")
        lines.append("```json")
        lines.append(json.dumps(response_headers, indent=2))
        lines.append("```\n")
        lines.append("### Body")
        lines.append("```")
        lines.append(body_text_preview)
        if truncated:
            lines.append("\n[... truncated ...]")
        lines.append("```")
        return "\n".join(lines)

    @mcp.tool(
        name="web_render",
        annotations={"title": "Web Render", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )
    async def web_render(params: WebRenderInput) -> str:
        wait_state = params.wait_until.strip().lower()
        if wait_state not in {"load", "domcontentloaded", "networkidle"}:
            return "Error: wait_until must be one of: load, domcontentloaded, networkidle"

        actions: List[Dict[str, Any]] = []
        if params.actions_json:
            try:
                parsed = json.loads(params.actions_json)
            except json.JSONDecodeError as exc:
                return f"Error: actions_json is not valid JSON: {exc}"
            if not isinstance(parsed, list):
                return "Error: actions_json must be a JSON array."
            actions = [a for a in parsed if isinstance(a, dict)]

        try:
            from playwright.async_api import async_playwright
        except Exception:
            return (
                "Error: Playwright is not available. Install with `pip install playwright` "
                "and run `playwright install chromium`."
            )

        timeout_ms = params.timeout * 1000
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                response = await page.goto(params.url, wait_until=wait_state, timeout=timeout_ms)

                executed = []
                for action in actions[:50]:
                    action_type = str(action.get("action", "")).strip().lower()
                    if action_type == "click":
                        selector = action.get("selector")
                        if selector:
                            await page.click(str(selector), timeout=timeout_ms)
                            executed.append({"action": "click", "selector": selector})
                    elif action_type == "type":
                        selector = action.get("selector")
                        text = action.get("text", "")
                        if selector:
                            await page.fill(str(selector), str(text), timeout=timeout_ms)
                            executed.append({"action": "type", "selector": selector, "text_len": len(str(text))})
                    elif action_type == "scroll":
                        x = int(action.get("x", 0))
                        y = int(action.get("y", 800))
                        await page.evaluate("window.scrollBy(arguments[0], arguments[1])", x, y)
                        executed.append({"action": "scroll", "x": x, "y": y})
                    elif action_type == "wait":
                        ms = int(action.get("ms", 500))
                        await page.wait_for_timeout(ms)
                        executed.append({"action": "wait", "ms": ms})

                html = await page.content()
                final_url = page.url
                title = await page.title()
                status = response.status if response else None

                await context.close()
                await browser.close()
        except Exception as exc:
            return f"Error: web_render failed: {exc}"

        upsert_response(
            url=final_url,
            method="RENDER",
            status=status,
            headers={"content-type": "text/html; charset=utf-8"},
            body=html.encode("utf-8", errors="replace"),
        )

        html_preview = html[:12000]
        html_truncated = len(html) > len(html_preview)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(
                {
                    "tool": "web_render",
                    "url": final_url,
                    "status": status,
                    "title": title,
                    "robots": "ignored",
                    "actions_executed": executed,
                    "html": html_preview,
                    "truncated": html_truncated,
                },
                indent=2,
            )

        lines = ["## Web Render\n"]
        lines.append(f"**URL:** `{final_url}`")
        lines.append(f"**Status:** `{status}`")
        lines.append(f"**Title:** {title}")
        lines.append("**Robots:** ignored")
        lines.append(f"**Actions executed:** {len(executed)}\n")
        lines.append("### Rendered HTML")
        lines.append("```html")
        lines.append(html_preview)
        if html_truncated:
            lines.append("\n<!-- truncated -->")
        lines.append("```")
        return "\n".join(lines)

    @mcp.tool(
        name="web_screenshot",
        annotations={"title": "Web Screenshot", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )
    async def web_screenshot(params: WebScreenshotInput) -> str:
        wait_state = params.wait_until.strip().lower()
        if wait_state not in {"load", "domcontentloaded", "networkidle"}:
            return "Error: wait_until must be one of: load, domcontentloaded, networkidle"

        try:
            from playwright.async_api import async_playwright
        except Exception:
            return (
                "Error: Playwright is not available. Install with `pip install playwright` "
                "and run `playwright install chromium`."
            )

        out_path = params.output_path
        if not out_path:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            os.makedirs("output", exist_ok=True)
            out_path = os.path.join("output", f"screenshot_{ts}.png")
        else:
            parent = os.path.dirname(out_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

        timeout_ms = params.timeout * 1000
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": params.viewport_width, "height": params.viewport_height},
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                response = await page.goto(params.url, wait_until=wait_state, timeout=timeout_ms)
                await page.screenshot(path=out_path, full_page=params.full_page)
                final_url = page.url
                title = await page.title()
                status = response.status if response else None
                await context.close()
                await browser.close()
        except Exception as exc:
            return f"Error: web_screenshot failed: {exc}"

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(
                {
                    "tool": "web_screenshot",
                    "url": final_url,
                    "status": status,
                    "title": title,
                    "path": out_path,
                    "full_page": params.full_page,
                    "viewport": {"width": params.viewport_width, "height": params.viewport_height},
                    "robots": "ignored",
                },
                indent=2,
            )

        lines = ["## Web Screenshot\n"]
        lines.append(f"**URL:** `{final_url}`")
        lines.append(f"**Status:** `{status}`")
        lines.append(f"**Title:** {title}")
        lines.append(f"**Saved to:** `{out_path}`")
        lines.append(f"**Full page:** `{params.full_page}`")
        lines.append(f"**Viewport:** `{params.viewport_width}x{params.viewport_height}`")
        lines.append("**Robots:** ignored")
        return "\n".join(lines)

    @mcp.tool(
        name="web_extract",
        annotations={"title": "Web Extract", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )
    async def web_extract(params: WebExtractInput) -> str:
        mode = params.mode.strip().lower()
        if mode not in {"readability", "css", "xpath"}:
            return "Error: mode must be one of: readability, css, xpath"

        html = ""
        source_url = params.url
        source_method = "GET"

        if params.prefer_cache:
            cached = get_cached(params.url, params.cache_method)
            if not cached and params.cache_method.upper() != "GET":
                cached = get_cached(params.url, "GET")
            if cached:
                html = cached.body.decode("utf-8", errors="replace")
                source_url = cached.url
                source_method = cached.method

        if not html:
            try:
                async with httpx.AsyncClient(timeout=params.timeout, follow_redirects=True) as client:
                    resp = await client.get(params.url)
            except Exception as exc:
                return f"Error: web_extract failed to fetch URL: {exc}"
            html = resp.text
            source_url = str(resp.url)
            source_method = "GET"
            upsert_response(
                url=source_url,
                method="GET",
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.content,
            )

        result: Dict[str, Any] = {"mode": mode, "url": source_url, "source_method": source_method}
        extracted_text = ""

        if mode == "readability":
            try:
                from readability import Document
            except Exception:
                return "Error: readability-lxml is not installed."

            doc = Document(html)
            summary_html = doc.summary(html_partial=True)
            title = doc.short_title()
            extracted_text = summary_html
            result["title"] = title
            result["content_html"] = summary_html

        elif mode == "css":
            if not params.selector:
                return "Error: selector is required when mode='css'"
            try:
                from selectolax.parser import HTMLParser
            except Exception:
                return "Error: selectolax is not installed."

            tree = HTMLParser(html)
            nodes = tree.css(params.selector)
            items = []
            for node in nodes[:200]:
                text = node.text(strip=True)
                if text:
                    items.append(text)
            extracted_text = "\n".join(items)
            result["selector"] = params.selector
            result["matches"] = len(nodes)
            result["items"] = items

        elif mode == "xpath":
            if not params.selector:
                return "Error: selector is required when mode='xpath'"
            try:
                from lxml import html as lxml_html
            except Exception:
                return "Error: lxml is not installed."

            doc = lxml_html.fromstring(html)
            raw_nodes = doc.xpath(params.selector)
            items = []
            for node in raw_nodes[:200]:
                if hasattr(node, "text_content"):
                    val = node.text_content().strip()
                else:
                    val = str(node).strip()
                if val:
                    items.append(val)
            extracted_text = "\n".join(items)
            result["selector"] = params.selector
            result["matches"] = len(raw_nodes)
            result["items"] = items

        if mode != "readability":
            result["content_text"] = extracted_text

        truncated = False
        if len(extracted_text) > params.max_chars:
            extracted_text = extracted_text[: params.max_chars]
            truncated = True

        if params.response_format == ResponseFormat.JSON:
            payload = {
                "tool": "web_extract",
                "robots": "ignored",
                **result,
                "preview": extracted_text,
                "truncated": truncated,
            }
            return json.dumps(payload, indent=2)

        lines = ["## Web Extract\n"]
        lines.append(f"**URL:** `{source_url}`")
        lines.append(f"**Mode:** `{mode}`")
        lines.append(f"**Source:** `{source_method}`")
        lines.append("**Robots:** ignored\n")
        if result.get("title"):
            lines.append(f"**Title:** {result['title']}")
        if result.get("selector"):
            lines.append(f"**Selector:** `{result['selector']}`")
        if result.get("matches") is not None:
            lines.append(f"**Matches:** {result['matches']}")
        lines.append("\n### Extracted")
        fence = "html" if mode == "readability" else "text"
        lines.append(f"```{fence}")
        lines.append(extracted_text)
        if truncated:
            lines.append("\n[... truncated ...]")
        lines.append("```")
        return "\n".join(lines)

    @mcp.tool(
        name="fingerprint_tech",
        annotations={"title": "Fingerprint Tech", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    )
    async def fingerprint_tech(params: FingerprintTechInput) -> str:
        html = ""
        headers: Dict[str, str] = {}
        final_url = params.url
        status = None

        if params.prefer_cache:
            cached = get_cached(params.url, "RENDER") or get_cached(params.url, "GET")
            if cached:
                html = cached.body.decode("utf-8", errors="replace")
                headers = {str(k).lower(): str(v) for k, v in cached.headers.items()}
                final_url = cached.url
                status = cached.status

        if not html:
            try:
                async with httpx.AsyncClient(timeout=params.timeout, follow_redirects=True) as client:
                    resp = await client.get(params.url)
            except Exception as exc:
                return f"Error: fingerprint_tech failed to fetch URL: {exc}"
            html = resp.text
            headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
            final_url = str(resp.url)
            status = resp.status_code
            upsert_response(
                url=final_url,
                method="GET",
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.content,
            )

        tech = set()

        server = headers.get("server")
        if server:
            tech.add(f"server:{server}")

        powered_by = headers.get("x-powered-by")
        if powered_by:
            tech.add(f"x-powered-by:{powered_by}")

        html_l = html.lower()
        if "wp-content" in html_l or "wordpress" in html_l:
            tech.add("WordPress")
        if "drupal-settings-json" in html_l or "drupal" in html_l:
            tech.add("Drupal")
        if "__next" in html_l or "_next/static" in html_l:
            tech.add("Next.js")
        if "react" in html_l and ("data-reactroot" in html_l or "react-dom" in html_l):
            tech.add("React")
        if "vue" in html_l and "__vue" in html_l:
            tech.add("Vue")
        if "angular" in html_l and "ng-" in html_l:
            tech.add("Angular")
        if "jquery" in html_l:
            tech.add("jQuery")
        if "bootstrap" in html_l:
            tech.add("Bootstrap")
        if "cloudflare" in headers.get("server", "").lower() or "cf-ray" in headers:
            tech.add("Cloudflare")

        try:
            from Wappalyzer import Wappalyzer, WebPage

            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(final_url, timeout=params.timeout)
            detected = wappalyzer.analyze(webpage)
            for item in detected:
                tech.add(str(item))
        except Exception:
            pass

        technologies = sorted(t for t in tech if t)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(
                {
                    "tool": "fingerprint_tech",
                    "url": final_url,
                    "status": status,
                    "technologies": technologies,
                    "robots": "ignored",
                },
                indent=2,
            )

        lines = ["## Fingerprint Tech\n"]
        lines.append(f"**URL:** `{final_url}`")
        lines.append(f"**Status:** `{status}`")
        lines.append("**Robots:** ignored\n")
        if not technologies:
            lines.append("_No technologies confidently detected._")
        else:
            for t in technologies:
                lines.append(f"- {t}")
        return "\n".join(lines)

    @mcp.tool(
        name="query_cache",
        annotations={"title": "Query Cache", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    )
    async def query_cache(params: QueryCacheInput) -> str:
        if params.url:
            entry = get_cached(params.url, params.method)
            if not entry:
                return f"No cache entry found for {params.method.upper()} {params.url}"

            body_text = entry.body.decode("utf-8", errors="replace")
            body_preview = body_text[:8000]
            truncated = len(body_text) > len(body_preview)

            if params.response_format == ResponseFormat.JSON:
                return json.dumps(
                    {
                        "tool": "query_cache",
                        "url": entry.url,
                        "method": entry.method,
                        "status": entry.status,
                        "headers": entry.headers,
                        "fetched_at": entry.fetched_at,
                        "content_hash": entry.content_hash,
                        "body": body_preview,
                        "truncated": truncated,
                    },
                    indent=2,
                )

            lines = ["## Cache Entry\n"]
            lines.append(f"**URL:** `{entry.url}`")
            lines.append(f"**Method:** `{entry.method}`")
            lines.append(f"**Status:** `{entry.status}`")
            lines.append(f"**Fetched at:** `{entry.fetched_at}`")
            lines.append(f"**Hash:** `{entry.content_hash}`\n")
            lines.append("### Body")
            lines.append("```")
            lines.append(body_preview)
            if truncated:
                lines.append("\n[... truncated ...]")
            lines.append("```")
            return "\n".join(lines)

        entries = list_cached(limit=params.limit)
        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"tool": "query_cache", "count": len(entries), "entries": entries}, indent=2)

        lines = ["## Cache Index\n"]
        lines.append(f"**Entries:** {len(entries)}\n")
        for idx, item in enumerate(entries, 1):
            lines.append(
                f"{idx}. `{item['method']}` `{item['url']}` status={item['status']} fetched_at={item['fetched_at']}"
            )
        return "\n".join(lines)
