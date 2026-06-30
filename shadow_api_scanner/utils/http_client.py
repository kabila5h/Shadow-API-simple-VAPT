"""
Async HTTP client wrapper for Shadow API Scanner.

Provides a reusable httpx-based async client with retry logic,
rate limiting, and response capture for proof-of-concept generation.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from shadow_api_scanner.core.config import ScanConfig


@dataclass
class CapturedRequest:
    """Stores a request/response pair for PoC evidence."""
    method: str
    url: str
    headers: dict
    body: Optional[str]
    status_code: int
    response_headers: dict
    response_body: str
    response_time_ms: float
    timestamp: str = ""

    def format_request(self) -> str:
        """Format as a cURL-like request string."""
        lines = [f"{self.method} {self.url}"]
        for k, v in self.headers.items():
            lines.append(f"  {k}: {v}")
        if self.body:
            lines.append(f"  Body: {self.body[:500]}")
        return "\n".join(lines)

    def format_response(self) -> str:
        """Format response summary."""
        body_preview = self.response_body[:1000] if self.response_body else ""
        return (
            f"HTTP {self.status_code} ({self.response_time_ms:.0f}ms)\n"
            f"  Content-Length: {len(self.response_body) if self.response_body else 0}\n"
            f"  Body: {body_preview}"
        )


class AsyncHTTPClient:
    """
    Managed async HTTP client with rate limiting and retry logic.

    Usage:
        async with AsyncHTTPClient(config) as client:
            captured = await client.request("GET", url)
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limit_delay = config.rate_limit_delay
        self._last_request_time = 0.0
        self._request_count = 0

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.request_timeout),
            follow_redirects=True,
            verify=False,  # Allow self-signed certs in testing
            headers=self.config.get_headers(),
            http2=True,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    async def _enforce_rate_limit(self):
        """Enforce minimum delay between requests."""
        if self._rate_limit_delay > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self._rate_limit_delay:
                await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json_body: Optional[Any] = None,
        data: Optional[str] = None,
        retries: int = 2,
        skip_rate_limit: bool = False,
    ) -> CapturedRequest:
        """
        Send an HTTP request and return a CapturedRequest with full details.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Additional headers to merge
            params: Query parameters
            json_body: JSON body (dict or list)
            data: Raw body string
            retries: Number of retry attempts
            skip_rate_limit: Skip rate limiting for this request

        Returns:
            CapturedRequest with request and response details.
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use 'async with' context.")

        if not skip_rate_limit:
            await self._enforce_rate_limit()

        merged_headers = dict(self.config.get_headers())
        if headers:
            merged_headers.update(headers)

        request_body = None
        if json_body is not None:
            import json as json_mod
            request_body = json_mod.dumps(json_body)
        elif data is not None:
            request_body = data

        last_error = None
        for attempt in range(retries + 1):
            try:
                start = time.monotonic()
                response = await self._client.request(
                    method=method.upper(),
                    url=url,
                    headers=merged_headers,
                    params=params,
                    json=json_body,
                    content=data.encode() if data and json_body is None else None,
                )
                elapsed_ms = (time.monotonic() - start) * 1000

                self._request_count += 1

                resp_body = ""
                try:
                    resp_body = response.text
                except Exception:
                    resp_body = "<binary or undecodable>"

                return CapturedRequest(
                    method=method.upper(),
                    url=str(response.url),
                    headers=merged_headers,
                    body=request_body,
                    status_code=response.status_code,
                    response_headers=dict(response.headers),
                    response_body=resp_body,
                    response_time_ms=elapsed_ms,
                )

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                last_error = e
                if attempt < retries:
                    await asyncio.sleep(1 * (attempt + 1))
                continue
            except Exception as e:
                last_error = e
                break

        # Return an error-state CapturedRequest
        return CapturedRequest(
            method=method.upper(),
            url=url,
            headers=merged_headers,
            body=request_body,
            status_code=0,
            response_headers={},
            response_body=f"ERROR: {str(last_error)}",
            response_time_ms=0,
        )

    async def get(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("PATCH", url, **kwargs)

    async def options(self, url: str, **kwargs) -> CapturedRequest:
        return await self.request("OPTIONS", url, **kwargs)

    @property
    def total_requests(self) -> int:
        return self._request_count
