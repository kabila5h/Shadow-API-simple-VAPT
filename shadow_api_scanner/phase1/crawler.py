"""
Phase 1: JavaScript Crawler

Crawls a target SPA URL and downloads all accessible frontend
JavaScript files from <script> tags, preload hints, and chunk references.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.utils.helpers import (
    is_js_file, resolve_url, hash_content,
)

logger = logging.getLogger("shadow_api_scanner")

# CDN domains to skip (we want app-specific JS only)
SKIP_DOMAINS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
    "fonts.googleapis.com", "www.googletagmanager.com",
    "www.google-analytics.com", "connect.facebook.net",
]


class JSFile:
    """Represents a downloaded JavaScript file."""

    def __init__(self, url: str, content: str, source: str = "html"):
        self.url = url
        self.content = content
        self.source = source
        self.hash = hash_content(content)
        self.size = len(content)

    def __repr__(self):
        return f"<JSFile url={self.url} size={self.size}>"


class JSCrawler:
    """
    Crawl and download all JavaScript files from a target SPA.

    Strategy:
    1. Fetch main HTML page
    2. Extract <script src> tags and preload hints
    3. Download each JS file
    4. Parse downloaded JS for chunk/dynamic import references
    5. Deduplicate by content hash
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.target_url = config.target_url
        self._visited: set[str] = set()
        self._js_files: dict[str, JSFile] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def crawl(self) -> list[JSFile]:
        """Execute the crawl and return all discovered JS files."""
        logger.info(f"🔍 Crawling JavaScript files from: {self.target_url}")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.js_download_timeout),
            follow_redirects=True, verify=False,
            headers={"User-Agent": self.config.user_agent}, http2=True,
        ) as client:
            self._client = client

            # Fetch main page
            html = await self._fetch(self.target_url)
            if not html:
                logger.error("Failed to fetch main page")
                return []

            # Extract JS references from HTML
            js_urls, inline_scripts = self._parse_html(html, self.target_url)
            logger.info(f"  Found {len(js_urls)} external JS, {len(inline_scripts)} inline")

            # Store inline scripts
            for i, script in enumerate(inline_scripts):
                if len(script.strip()) > 50:
                    self._store(JSFile(f"{self.target_url}#inline-{i}", script, "inline"))

            # Download external JS concurrently
            await asyncio.gather(
                *[self._download(url) for url in js_urls],
                return_exceptions=True,
            )

            # Discover chunk references in downloaded JS
            chunk_urls: set[str] = set()
            for jf in list(self._js_files.values()):
                chunk_urls.update(self._find_chunks(jf.content, jf.url))
            chunk_urls -= self._visited

            if chunk_urls:
                logger.info(f"  Discovered {len(chunk_urls)} chunk files")
                await asyncio.gather(
                    *[self._download(u) for u in chunk_urls],
                    return_exceptions=True,
                )

        result = list(self._js_files.values())
        total_bytes = sum(f.size for f in result)
        logger.info(f"✅ Crawl complete: {len(result)} unique JS files ({total_bytes:,} bytes)")
        return result

    async def _fetch(self, url: str) -> Optional[str]:
        try:
            r = await self._client.get(url)
            r.raise_for_status()
            return r.text
        except Exception as e:
            logger.warning(f"  Failed to fetch {url}: {e}")
            return None

    async def _download(self, url: str):
        if url in self._visited or len(self._js_files) >= self.config.max_js_files:
            return
        self._visited.add(url)
        try:
            r = await self._client.get(url)
            if r.status_code == 200 and len(r.text) > 10:
                self._store(JSFile(url, r.text, "external"))
                logger.debug(f"  ↓ {url} ({len(r.text):,}B)")
        except Exception as e:
            logger.debug(f"  ✗ {url}: {e}")

    def _store(self, jf: JSFile):
        if jf.hash not in self._js_files:
            self._js_files[jf.hash] = jf

    def _parse_html(self, html: str, page_url: str) -> tuple[set[str], list[str]]:
        soup = BeautifulSoup(html, "lxml")
        urls: set[str] = set()
        inline: list[str] = []

        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                full = resolve_url(page_url, src)
                if self._is_relevant(full):
                    urls.add(full)
            elif tag.string:
                inline.append(tag.string)

        for link in soup.find_all("link"):
            href = link.get("href", "")
            rel = " ".join(link.get("rel", []))
            if href and ("preload" in rel or "modulepreload" in rel) and is_js_file(href):
                full = resolve_url(page_url, href)
                if self._is_relevant(full):
                    urls.add(full)

        return urls, inline

    def _find_chunks(self, js: str, base_url: str) -> set[str]:
        chunks: set[str] = set()
        # String paths ending in .js
        for m in re.finditer(r'["\']((?:/|\./)[\w/.-]*\.(?:js|mjs))["\']', js):
            full = resolve_url(base_url, m.group(1))
            if self._is_relevant(full):
                chunks.add(full)
        # Dynamic imports
        for m in re.finditer(r'import\s*\(\s*["\']([\\w/.-]+)["\']', js):
            path = m.group(1)
            if not path.endswith(".js"):
                path += ".js"
            full = resolve_url(base_url, path)
            if self._is_relevant(full):
                chunks.add(full)
        return chunks

    def _is_relevant(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.hostname and any(parsed.hostname.endswith(d) for d in SKIP_DOMAINS):
            return False
        return True
