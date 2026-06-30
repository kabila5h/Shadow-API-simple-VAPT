"""
Phase 2: OpenAPI/Swagger Specification Comparator

Downloads and parses OpenAPI/Swagger specs (if available) to
determine which endpoints are documented vs. shadow.
"""

from __future__ import annotations

import json
import logging
from typing import Optional
from urllib.parse import urljoin

import httpx

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, EndpointSource

logger = logging.getLogger("shadow_api_scanner")

# Common paths where OpenAPI specs are published
COMMON_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/openapi.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/.well-known/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
]


class SpecComparator:
    """
    Discover and parse OpenAPI/Swagger specs to build a documented API inventory.

    Compares discovered endpoints against the spec to flag shadow APIs.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.spec_data: Optional[dict] = None
        self.documented_paths: set[str] = set()

    async def discover_and_parse(self) -> list[APIEndpoint]:
        """
        Attempt to find and parse an OpenAPI specification.

        Returns:
            List of documented APIEndpoint objects.
        """
        logger.info("  🔎 Searching for OpenAPI/Swagger specification...")

        spec_content = None

        # Try user-provided spec first
        if self.config.openapi_spec_file:
            try:
                with open(self.config.openapi_spec_file, "r") as f:
                    spec_content = f.read()
                logger.info(f"  Loaded spec from file: {self.config.openapi_spec_file}")
            except Exception as e:
                logger.warning(f"  Failed to load spec file: {e}")

        if not spec_content and self.config.openapi_spec_url:
            spec_content = await self._fetch_spec(self.config.openapi_spec_url)

        # Auto-discover spec
        if not spec_content:
            async with httpx.AsyncClient(
                timeout=10, verify=False, follow_redirects=True
            ) as client:
                for path in COMMON_SPEC_PATHS:
                    url = urljoin(self.config.target_url, path)
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            text = resp.text
                            if self._looks_like_spec(text):
                                spec_content = text
                                logger.info(f"  ✅ Found OpenAPI spec at: {url}")
                                break
                    except Exception:
                        continue

        if not spec_content:
            logger.info("  No OpenAPI specification found.")
            return []

        # Parse the spec
        return self._parse_spec(spec_content)

    async def _fetch_spec(self, url: str) -> Optional[str]:
        """Fetch spec from URL."""
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text
        except Exception as e:
            logger.warning(f"  Failed to fetch spec from {url}: {e}")
        return None

    def _looks_like_spec(self, content: str) -> bool:
        """Quick check if content looks like an OpenAPI spec."""
        indicators = ["openapi", "swagger", "paths", "info"]
        content_lower = content[:2000].lower()
        return sum(1 for i in indicators if i in content_lower) >= 2

    def _parse_spec(self, content: str) -> list[APIEndpoint]:
        """Parse OpenAPI JSON spec into endpoint list."""
        try:
            spec = json.loads(content)
        except json.JSONDecodeError:
            try:
                import yaml  # type: ignore
                spec = yaml.safe_load(content)
            except Exception:
                logger.warning("  Failed to parse specification content")
                return []

        self.spec_data = spec
        endpoints = []

        # Determine base URL from spec
        base_url = self.config.target_url
        if "servers" in spec:
            servers = spec["servers"]
            if servers and "url" in servers[0]:
                server_url = servers[0]["url"]
                if server_url.startswith("/"):
                    base_url = urljoin(self.config.target_url, server_url)
                elif server_url.startswith("http"):
                    base_url = server_url

        # Extract paths
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                    full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                    self.documented_paths.add(f"{method.upper()}:{path}")
                    endpoints.append(
                        APIEndpoint(
                            url=full_url,
                            method=method.upper(),
                            source=EndpointSource.OPENAPI_SPEC,
                        )
                    )

        logger.info(f"  Parsed {len(endpoints)} documented endpoints from spec")
        return endpoints

    def is_documented(self, endpoint: APIEndpoint) -> bool:
        """Check if an endpoint exists in the documented spec."""
        if not self.documented_paths:
            return False

        from urllib.parse import urlparse
        path = urlparse(endpoint.url).path

        # Direct match
        key = f"{endpoint.method}:{path}"
        if key in self.documented_paths:
            return True

        # Try without trailing slash
        key2 = f"{endpoint.method}:{path.rstrip('/')}"
        if key2 in self.documented_paths:
            return True

        # Try parameterized match
        for doc_key in self.documented_paths:
            doc_method, doc_path = doc_key.split(":", 1)
            if doc_method != endpoint.method:
                continue
            if self._paths_match(doc_path, path):
                return True

        return False

    def _paths_match(self, pattern: str, actual: str) -> bool:
        """Check if a parameterized path pattern matches an actual path."""
        import re
        # Convert {param} to regex
        regex_pattern = re.sub(r"\{[^}]+\}", r"[^/]+", pattern)
        regex_pattern = "^" + regex_pattern.rstrip("/") + "/?$"
        return bool(re.match(regex_pattern, actual))
