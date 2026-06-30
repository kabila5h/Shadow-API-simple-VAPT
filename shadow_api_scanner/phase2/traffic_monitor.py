"""
Phase 2: Dynamic Traffic Monitor

Launches the SPA in a headless browser (Playwright) and captures
all network traffic (XHR, Fetch, WebSocket) to discover API
endpoints that are only triggered at runtime.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional
from urllib.parse import urlparse

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, EndpointSource, EndpointType
from shadow_api_scanner.utils.helpers import is_api_url, normalize_url

logger = logging.getLogger("shadow_api_scanner")


class TrafficMonitor:
    """
    Capture live API traffic from a SPA using Playwright's network interception.

    Launches a headless Chromium browser, navigates to the target URL,
    interacts with the page, and records all network requests/responses.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.captured_endpoints: list[APIEndpoint] = []
        self._captured_urls: set[str] = set()

    async def run(self) -> list[APIEndpoint]:
        """
        Launch browser, capture traffic, return discovered endpoints.

        Returns:
            List of APIEndpoint objects discovered during dynamic monitoring.
        """
        logger.info("=" * 60)
        logger.info("🌐 PHASE 2: Dynamic Traffic Monitoring")
        logger.info("=" * 60)

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.error(
                "Playwright is not installed. Install with: "
                "pip install playwright && python -m playwright install chromium"
            )
            return []

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=self.config.browser_headless,
                )
                context = await browser.new_context(
                    user_agent=self.config.user_agent,
                    ignore_https_errors=True,
                    viewport={"width": 1920, "height": 1080},
                )

                page = await context.new_page()

                # Set up network interception
                page.on("request", self._on_request)
                page.on("response", self._on_response)

                logger.info(f"  Navigating to: {self.config.target_url}")

                try:
                    await page.goto(
                        self.config.target_url,
                        wait_until="networkidle",
                        timeout=self.config.browser_timeout * 1000,
                    )
                except Exception as e:
                    logger.warning(f"  Page load warning: {e}")

                # Wait for additional XHR/fetch calls
                logger.info(
                    f"  Waiting {self.config.wait_after_load}s for async requests..."
                )
                await asyncio.sleep(self.config.wait_after_load)

                # Try to trigger more API calls via basic interaction
                await self._interact_with_page(page)

                # Wait a bit more after interaction
                await asyncio.sleep(3)

                await browser.close()

        except Exception as e:
            logger.error(f"  Dynamic monitoring failed: {e}")
            return []

        logger.info(f"\n📊 Phase 2 Results:")
        logger.info(f"  API requests captured: {len(self.captured_endpoints)}")
        for ep in self.captured_endpoints:
            logger.info(f"    {ep.method:6s} [{ep.status_code}] {ep.url}")

        return self.captured_endpoints

    def _on_request(self, request):
        """Handle intercepted request."""
        url = request.url
        method = request.method
        resource_type = request.resource_type

        # Filter for API-relevant requests
        if resource_type in ("xhr", "fetch", "websocket", "other"):
            if self._is_api_request(url, resource_type):
                key = f"{method}:{normalize_url(url)}"
                if key not in self._captured_urls:
                    self._captured_urls.add(key)

                    ep_type = EndpointType.REST
                    if resource_type == "websocket":
                        ep_type = EndpointType.WEBSOCKET
                    elif "graphql" in url.lower():
                        ep_type = EndpointType.GRAPHQL

                    headers = {}
                    try:
                        headers = dict(request.headers)
                    except Exception:
                        pass

                    endpoint = APIEndpoint(
                        url=url,
                        method=method,
                        source=EndpointSource.DYNAMIC_TRAFFIC,
                        endpoint_type=ep_type,
                        headers=headers,
                        content_type=headers.get("content-type"),
                    )
                    self.captured_endpoints.append(endpoint)
                    logger.debug(f"    📡 Captured: {method} {url}")

    def _on_response(self, response):
        """Update captured endpoints with response data."""
        url = response.url
        method = response.request.method
        key = f"{method}:{normalize_url(url)}"

        # Find matching endpoint and update with response info
        for ep in self.captured_endpoints:
            if f"{ep.method}:{normalize_url(ep.url)}" == key and ep.status_code is None:
                ep.status_code = response.status
                try:
                    ep.response_headers = dict(response.headers)
                except Exception:
                    pass
                break

    async def _interact_with_page(self, page):
        """
        Perform basic interactions to trigger more API calls.

        Scrolls, clicks navigation elements, and explores common patterns.
        """
        logger.info("  Performing page interactions to discover hidden APIs...")

        try:
            # Scroll to bottom to trigger lazy loading
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)

            # Click on navigation links
            nav_selectors = [
                "nav a", "a[href]", "[role='navigation'] a",
                ".nav a", ".menu a", ".sidebar a",
                "button", "[role='button']", "[role='tab']",
            ]
            for selector in nav_selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for elem in elements[:5]:  # Limit clicks per selector
                        try:
                            if await elem.is_visible():
                                await elem.click(timeout=2000)
                                await asyncio.sleep(0.5)
                        except Exception:
                            continue
                except Exception:
                    continue

            # Scroll back to top
            await page.evaluate("window.scrollTo(0, 0)")
            await asyncio.sleep(1)

        except Exception as e:
            logger.debug(f"  Interaction error (non-critical): {e}")

    def _is_api_request(self, url: str, resource_type: str) -> bool:
        """Determine if a request is an API call worth capturing."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Skip static assets
        static_extensions = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
            ".mp4", ".webm", ".webp", ".avif",
        )
        if any(path.endswith(ext) for ext in static_extensions):
            return False

        # Skip known tracking/analytics
        skip_hosts = [
            "google-analytics.com", "googletagmanager.com",
            "facebook.com", "doubleclick.net", "analytics",
            "sentry.io", "hotjar.com", "mixpanel.com",
        ]
        if parsed.hostname and any(h in parsed.hostname for h in skip_hosts):
            return False

        # WebSocket always counts
        if resource_type == "websocket":
            return True

        # Check if it looks like an API call
        if is_api_url(url):
            return True

        # XHR/Fetch that returns JSON is likely an API
        if resource_type in ("xhr", "fetch"):
            return True

        return False
