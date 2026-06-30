"""
Phase 1: JavaScript Parser

Extracts API endpoints, base URLs, tokens, and request patterns
from JavaScript source code using regex-based pattern matching.
"""

from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from shadow_api_scanner.core.models import APIEndpoint, EndpointSource, EndpointType
from shadow_api_scanner.utils.helpers import is_api_url, resolve_url

logger = logging.getLogger("shadow_api_scanner")


# ──────────────────────────────────────────────────────────────
# Regex patterns for API endpoint extraction
# ──────────────────────────────────────────────────────────────

# Matches fetch(), axios, httpx, $http calls
FETCH_PATTERNS = [
    # fetch("url") or fetch('url')
    re.compile(r"""fetch\s*\(\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
    # fetch(baseUrl + "/path") — capture the string literal part
    re.compile(r"""fetch\s*\([^)]*["'`](/[^"'`\s]{2,})["'`]""", re.I),
    # axios.get/post/put/delete("url")
    re.compile(
        r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["'`](https?://[^"'`\s]+)["'`]""",
        re.I,
    ),
    re.compile(
        r"""axios\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*["'`](/[^"'`\s]{2,})["'`]""",
        re.I,
    ),
    # axios({ url: "..." })
    re.compile(r"""url\s*:\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
    re.compile(r"""url\s*:\s*["'`](/api[^"'`\s]*)["'`]""", re.I),
    # XMLHttpRequest.open("METHOD", "url")
    re.compile(
        r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`](https?://[^"'`\s]+)["'`]""",
        re.I,
    ),
    re.compile(
        r"""\.open\s*\(\s*["'`](?:GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`](/[^"'`\s]{2,})["'`]""",
        re.I,
    ),
]

# HTTP method extraction from various patterns
METHOD_PATTERNS = [
    re.compile(r"""method\s*:\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]""", re.I),
    re.compile(r"""\.open\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["'`]""", re.I),
    re.compile(r"""axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(""", re.I),
    re.compile(r"""\.\s*(get|post|put|delete|patch)\s*\(\s*["'`]""", re.I),
]

# Full URL patterns (absolute URLs in strings)
URL_PATTERNS = [
    re.compile(r"""["'`](https?://[a-zA-Z0-9._-]+(?::\d+)?/[^"'`\s]{2,})["'`]"""),
]

# Relative API path patterns
API_PATH_PATTERNS = [
    re.compile(r"""["'`](/api/v?\d*/[^"'`\s]{2,})["'`]"""),
    re.compile(r"""["'`](/api/[^"'`\s]{2,})["'`]"""),
    re.compile(r"""["'`](/v[1-4]/[^"'`\s]{2,})["'`]"""),
    re.compile(r"""["'`](/graphql[^"'`\s]*)["'`]"""),
    re.compile(r"""["'`](/rest/[^"'`\s]{2,})["'`]"""),
]

# Base URL patterns
BASE_URL_PATTERNS = [
    re.compile(r"""(?:baseURL|base_url|baseUrl|BASE_URL|apiUrl|API_URL|apiBase)\s*[:=]\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
    re.compile(r"""(?:API_BASE|BACKEND_URL|SERVER_URL|API_ENDPOINT)\s*[:=]\s*["'`](https?://[^"'`\s]+)["'`]""", re.I),
]

# WebSocket patterns
WEBSOCKET_PATTERNS = [
    re.compile(r"""["'`](wss?://[^"'`\s]+)["'`]"""),
    re.compile(r"""new\s+WebSocket\s*\(\s*["'`](wss?://[^"'`\s]+)["'`]"""),
]

# GraphQL operation patterns
GRAPHQL_PATTERNS = [
    re.compile(r"""(?:query|mutation|subscription)\s+(\w+)\s*[({]""", re.I),
    re.compile(r"""gql\s*`\s*(?:query|mutation|subscription)\s+(\w+)""", re.I),
]

# API key / token patterns
SECRET_PATTERNS = [
    re.compile(r"""(?:api[_-]?key|apikey|api_token|access_token|secret_key|auth_token|bearer)\s*[:=]\s*["'`]([^"'`\s]{8,})["'`]""", re.I),
    re.compile(r"""["'`]((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,})["'`]"""),  # Stripe-like
    re.compile(r"""["'`](AIza[A-Za-z0-9_-]{35})["'`]"""),  # Google API key
    re.compile(r"""["'`](ghp_[A-Za-z0-9]{36})["'`]"""),  # GitHub PAT
    re.compile(r"""["'`](AKIA[0-9A-Z]{16})["'`]"""),  # AWS key
]

# Route definition patterns (React Router, Vue Router, Angular)
ROUTE_PATTERNS = [
    re.compile(r"""path\s*:\s*["'`](/[^"'`\s]*)["'`]"""),
    re.compile(r"""<Route\s+[^>]*path\s*=\s*["'`](/[^"'`\s]*)["'`]""", re.I),
    re.compile(r"""navigate\s*\(\s*["'`](/[^"'`\s]*)["'`]""", re.I),
]


class JSParser:
    """
    Parse JavaScript source code to extract API-related information.

    Extracts:
      - API endpoints (REST, GraphQL, WebSocket)
      - Base URLs and route patterns
      - Exposed API keys/tokens
      - HTTP methods and request configurations
    """

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.base_urls_discovered: list[str] = []
        self.secrets_found: list[dict] = []
        self.graphql_operations: list[str] = []

    def parse(self, js_content: str, source_url: str = "") -> list[APIEndpoint]:
        """
        Parse a JavaScript file and extract all API endpoints.

        Args:
            js_content: Raw JavaScript source code
            source_url: URL where this JS file was loaded from

        Returns:
            List of discovered APIEndpoint objects
        """
        endpoints: list[APIEndpoint] = []
        seen_urls: set[str] = set()

        # 1. Extract base URLs
        self._extract_base_urls(js_content)

        # 2. Extract secrets
        self._extract_secrets(js_content, source_url)

        # 3. Extract fetch/axios/XHR endpoints
        for pattern in FETCH_PATTERNS:
            for match in pattern.finditer(js_content):
                url = match.group(1)
                full_url = self._resolve(url)
                if full_url and full_url not in seen_urls:
                    seen_urls.add(full_url)
                    method = self._detect_method_near(js_content, match.start())
                    endpoints.append(
                        APIEndpoint(
                            url=full_url,
                            method=method,
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.REST,
                        )
                    )

        # 4. Extract absolute URLs
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(js_content):
                url = match.group(1)
                if is_api_url(url) and url not in seen_urls:
                    seen_urls.add(url)
                    endpoints.append(
                        APIEndpoint(
                            url=url,
                            method="GET",
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.REST,
                            confidence=0.7,
                        )
                    )

        # 5. Extract relative API paths
        for pattern in API_PATH_PATTERNS:
            for match in pattern.finditer(js_content):
                path = match.group(1)
                full_url = self._resolve(path)
                if full_url and full_url not in seen_urls:
                    seen_urls.add(full_url)
                    endpoints.append(
                        APIEndpoint(
                            url=full_url,
                            method="GET",
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.REST,
                            confidence=0.8,
                        )
                    )

        # 6. Extract WebSocket endpoints
        for pattern in WEBSOCKET_PATTERNS:
            for match in pattern.finditer(js_content):
                ws_url = match.group(1)
                if ws_url not in seen_urls:
                    seen_urls.add(ws_url)
                    endpoints.append(
                        APIEndpoint(
                            url=ws_url,
                            method="WEBSOCKET",
                            source=EndpointSource.STATIC_JS,
                            js_file_source=source_url,
                            endpoint_type=EndpointType.WEBSOCKET,
                        )
                    )

        # 7. Extract GraphQL operations
        for pattern in GRAPHQL_PATTERNS:
            for match in pattern.finditer(js_content):
                op_name = match.group(1)
                if op_name not in self.graphql_operations:
                    self.graphql_operations.append(op_name)

        # If we found GraphQL operations but no GraphQL endpoint, add default
        if self.graphql_operations:
            gql_url = self._resolve("/graphql")
            if gql_url and gql_url not in seen_urls:
                endpoints.append(
                    APIEndpoint(
                        url=gql_url,
                        method="POST",
                        source=EndpointSource.STATIC_JS,
                        js_file_source=source_url,
                        endpoint_type=EndpointType.GRAPHQL,
                    )
                )

        return endpoints

    def _resolve(self, url: str) -> Optional[str]:
        """Resolve a URL against discovered base URLs or the target URL."""
        if url.startswith(("http://", "https://", "ws://", "wss://")):
            return url
        if url.startswith("/"):
            # Try discovered base URLs first
            for base in self.base_urls_discovered:
                return urljoin(base, url)
            return urljoin(self.base_url, url)
        return None

    def _extract_base_urls(self, js_content: str):
        """Extract base URL definitions from JS."""
        for pattern in BASE_URL_PATTERNS:
            for match in pattern.finditer(js_content):
                base = match.group(1).rstrip("/")
                if base not in self.base_urls_discovered:
                    self.base_urls_discovered.append(base)
                    logger.debug(f"    Base URL discovered: {base}")

    def _extract_secrets(self, js_content: str, source_url: str):
        """Extract exposed API keys/tokens from JS."""
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(js_content):
                secret = match.group(1)
                self.secrets_found.append({
                    "value": secret,
                    "source": source_url,
                    "pattern": pattern.pattern[:50],
                })
                logger.warning(f"    ⚠️  Exposed secret found in {source_url}: {secret[:8]}...")

    def _detect_method_near(self, content: str, pos: int) -> str:
        """Try to detect the HTTP method used near a URL reference."""
        # Look at surrounding context (200 chars before the URL)
        start = max(0, pos - 200)
        context = content[start:pos + 50]

        for pattern in METHOD_PATTERNS:
            m = pattern.search(context)
            if m:
                return m.group(1).upper()

        # Default heuristic: if the context has "body" or "data", likely POST
        if re.search(r"\bbody\b|\bdata\b|\bpayload\b", context, re.I):
            return "POST"

        return "GET"
