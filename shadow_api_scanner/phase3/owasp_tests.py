"""
Phase 3: OWASP API Security Top 10 Tests

Implements automated security tests for each OWASP API category.
Each test sends crafted requests and analyzes responses to detect vulnerabilities.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from shadow_api_scanner.core.config import (
    OWASP_CATEGORIES, SSRF_PAYLOADS, SENSITIVE_PATTERNS, AUTH_BYPASS_HEADERS,
)
from shadow_api_scanner.core.models import (
    APIEndpoint, Vulnerability, RiskLevel, VulnStatus,
)
from shadow_api_scanner.phase3.fuzzer import Fuzzer
from shadow_api_scanner.utils.http_client import AsyncHTTPClient, CapturedRequest

logger = logging.getLogger("shadow_api_scanner")


class OWASPTestSuite:
    """Runs all 10 OWASP API Security tests against an endpoint."""

    def __init__(self, client: AsyncHTTPClient, fuzzer: Fuzzer):
        self.client = client
        self.fuzzer = fuzzer

    async def run_all(self, endpoint: APIEndpoint) -> list[Vulnerability]:
        """Run all applicable OWASP tests against an endpoint."""
        vulns: list[Vulnerability] = []
        tests = [
            self.test_bola,
            self.test_broken_auth,
            self.test_broken_property_auth,
            self.test_unrestricted_resource,
            self.test_broken_function_auth,
            self.test_sensitive_business_flow,
            self.test_ssrf,
            self.test_security_misconfig,
            self.test_improper_inventory,
            self.test_unsafe_consumption,
        ]
        for test_fn in tests:
            try:
                result = await test_fn(endpoint)
                if result:
                    vulns.extend(result if isinstance(result, list) else [result])
            except Exception as e:
                logger.debug(f"    Test {test_fn.__name__} error: {e}")
        return vulns

    # ── API1: Broken Object Level Authorization (BOLA) ──

    async def test_bola(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for BOLA/IDOR by manipulating object IDs in the URL."""
        vulns = []
        cat = OWASP_CATEGORIES["API1"]
        parsed = urlparse(ep.url)
        path_parts = [p for p in parsed.path.split("/") if p]

        # Find numeric segments that could be object IDs
        id_indices = [i for i, p in enumerate(path_parts) if p.isdigit()]
        if not id_indices:
            # Try UUID-like segments
            id_indices = [i for i, p in enumerate(path_parts)
                          if re.match(r'^[a-f0-9-]{8,}$', p, re.I)]

        if not id_indices:
            return vulns

        for idx in id_indices:
            original_id = path_parts[idx]
            for variant_id in self.fuzzer.generate_id_variants(original_id)[:5]:
                if variant_id == original_id:
                    continue
                new_parts = list(path_parts)
                new_parts[idx] = variant_id
                new_url = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(new_parts)}"
                if parsed.query:
                    new_url += f"?{parsed.query}"

                captured = await self.client.request(ep.method, new_url)
                if captured.status_code in (200, 201) and captured.status_code != 0:
                    vulns.append(Vulnerability(
                        endpoint_id=ep.id, owasp_category="API1",
                        owasp_name=cat["name"],
                        title=f"BOLA: Accessible with ID={variant_id}",
                        description=f"Endpoint returned {captured.status_code} when object ID "
                                    f"was changed from {original_id} to {variant_id}.",
                        severity=RiskLevel.CRITICAL, status=VulnStatus.POTENTIAL,
                        risk_score=cat["base_score"],
                        poc_request=captured.format_request(),
                        poc_response=captured.format_response(),
                        poc_status_code=captured.status_code,
                        remediation="Implement object-level authorization checks. Verify the requesting "
                                    "user has permission to access the specific object.",
                        cwe_id="CWE-639",
                    ))
                    break  # One finding per ID position is enough
        return vulns

    # ── API2: Broken Authentication ──

    async def test_broken_auth(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for authentication bypass by modifying/removing auth headers."""
        vulns = []
        cat = OWASP_CATEGORIES["API2"]

        # First, get baseline response with current auth
        baseline = await self.client.request(ep.method, ep.url)

        for auth_variant in self.fuzzer.generate_auth_variants()[:5]:
            captured = await self.client.request(
                ep.method, ep.url, headers=auth_variant
            )
            if (captured.status_code in (200, 201, 204) and
                    captured.status_code != 0 and
                    baseline.status_code in (200, 201, 204)):
                # Both with and without auth succeed — potential bypass
                if not auth_variant or not auth_variant.get("Authorization"):
                    vulns.append(Vulnerability(
                        endpoint_id=ep.id, owasp_category="API2",
                        owasp_name=cat["name"],
                        title="Auth Bypass: Endpoint accessible without authentication",
                        description="Endpoint returns successful response without valid authentication headers.",
                        severity=RiskLevel.CRITICAL, status=VulnStatus.POTENTIAL,
                        risk_score=cat["base_score"],
                        poc_request=captured.format_request(),
                        poc_response=captured.format_response(),
                        poc_status_code=captured.status_code,
                        remediation="Enforce authentication on all API endpoints. Use proven auth mechanisms.",
                        cwe_id="CWE-306",
                    ))
                    break
        return vulns

    # ── API3: Broken Object Property Level Authorization ──

    async def test_broken_property_auth(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for mass assignment / excessive data exposure."""
        vulns = []
        cat = OWASP_CATEGORIES["API3"]

        # Test excessive data exposure — check if response contains sensitive fields
        captured = await self.client.request(ep.method, ep.url)
        if captured.status_code in (200, 201) and captured.response_body:
            sensitive_found = []
            for pattern_name, pattern in SENSITIVE_PATTERNS.items():
                if re.search(pattern, captured.response_body):
                    sensitive_found.append(pattern_name)

            if sensitive_found:
                vulns.append(Vulnerability(
                    endpoint_id=ep.id, owasp_category="API3",
                    owasp_name=cat["name"],
                    title=f"Excessive Data Exposure: {', '.join(sensitive_found[:3])}",
                    description=f"Response contains potentially sensitive data patterns: "
                                f"{', '.join(sensitive_found)}",
                    severity=RiskLevel.HIGH, status=VulnStatus.POTENTIAL,
                    risk_score=cat["base_score"],
                    poc_request=captured.format_request(),
                    poc_response=captured.format_response(),
                    poc_status_code=captured.status_code,
                    poc_evidence=f"Sensitive patterns detected: {sensitive_found}",
                    remediation="Filter response data on the server side. Only return properties "
                                "the user is authorized to see.",
                    cwe_id="CWE-213",
                ))

            # Test mass assignment — try adding extra properties
            if ep.method in ("POST", "PUT", "PATCH"):
                evil_body = {"role": "admin", "isAdmin": True, "is_superuser": True}
                mass_captured = await self.client.request(
                    ep.method, ep.url, json_body=evil_body
                )
                if mass_captured.status_code in (200, 201):
                    body = mass_captured.response_body.lower()
                    if "admin" in body or "superuser" in body:
                        vulns.append(Vulnerability(
                            endpoint_id=ep.id, owasp_category="API3",
                            owasp_name=cat["name"],
                            title="Mass Assignment: Admin properties accepted",
                            description="Server accepted privileged properties in request body.",
                            severity=RiskLevel.HIGH, status=VulnStatus.POTENTIAL,
                            risk_score=8.0,
                            poc_request=mass_captured.format_request(),
                            poc_response=mass_captured.format_response(),
                            poc_status_code=mass_captured.status_code,
                            remediation="Whitelist allowed properties. Never bind request data directly to models.",
                            cwe_id="CWE-915",
                        ))
        return vulns

    # ── API4: Unrestricted Resource Consumption ──

    async def test_unrestricted_resource(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for missing rate limiting."""
        vulns = []
        cat = OWASP_CATEGORIES["API4"]
        success_count = 0
        total_requests = 20

        tasks = []
        for _ in range(total_requests):
            tasks.append(self.client.request(ep.method, ep.url, skip_rate_limit=True))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, CapturedRequest) and r.status_code in (200, 201, 204):
                success_count += 1

        if success_count >= total_requests * 0.9:
            vulns.append(Vulnerability(
                endpoint_id=ep.id, owasp_category="API4",
                owasp_name=cat["name"],
                title=f"No Rate Limiting: {success_count}/{total_requests} requests succeeded",
                description=f"Sent {total_requests} rapid requests; {success_count} returned success. "
                            f"No rate limiting detected.",
                severity=RiskLevel.HIGH, status=VulnStatus.POTENTIAL,
                risk_score=cat["base_score"],
                remediation="Implement rate limiting per client/IP. Use throttling mechanisms.",
                cwe_id="CWE-770",
            ))
        return vulns

    # ── API5: Broken Function Level Authorization ──

    async def test_broken_function_auth(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for function-level auth by trying different HTTP methods and admin paths."""
        vulns = []
        cat = OWASP_CATEGORIES["API5"]
        parsed = urlparse(ep.url)

        # Test method switching
        original_method = ep.method
        for method in self.fuzzer.generate_method_variants():
            if method == original_method or method in ("OPTIONS", "HEAD"):
                continue
            captured = await self.client.request(method, ep.url)
            if captured.status_code in (200, 201, 204) and captured.status_code != 0:
                vulns.append(Vulnerability(
                    endpoint_id=ep.id, owasp_category="API5",
                    owasp_name=cat["name"],
                    title=f"Method Override: {method} accepted (original: {original_method})",
                    description=f"Endpoint accepts {method} method in addition to {original_method}.",
                    severity=RiskLevel.HIGH, status=VulnStatus.POTENTIAL,
                    risk_score=cat["base_score"],
                    poc_request=captured.format_request(),
                    poc_response=captured.format_response(),
                    poc_status_code=captured.status_code,
                    remediation="Restrict allowed HTTP methods per endpoint. Implement proper RBAC.",
                    cwe_id="CWE-285",
                ))
                break

        # Test admin path variations
        admin_paths = ["/admin", "/internal", "/debug", "/manage", "/config"]
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in admin_paths:
            url = base + path
            captured = await self.client.request("GET", url)
            if captured.status_code in (200, 301, 302) and captured.status_code != 0:
                vulns.append(Vulnerability(
                    endpoint_id=ep.id, owasp_category="API5",
                    owasp_name=cat["name"],
                    title=f"Admin Endpoint Exposed: {path}",
                    description=f"Administrative endpoint {path} returned HTTP {captured.status_code}.",
                    severity=RiskLevel.CRITICAL, status=VulnStatus.POTENTIAL,
                    risk_score=9.0,
                    poc_request=captured.format_request(),
                    poc_response=captured.format_response(),
                    poc_status_code=captured.status_code,
                    remediation="Restrict admin endpoints with strong authorization. Deny by default.",
                    cwe_id="CWE-285",
                ))
        return vulns

    # ── API6: Unrestricted Access to Sensitive Business Flows ──

    async def test_sensitive_business_flow(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for unrestricted access to sensitive business flows."""
        vulns = []
        cat = OWASP_CATEGORIES["API6"]
        sensitive_keywords = ["purchase", "transfer", "payment", "checkout",
                              "withdraw", "send", "order", "subscribe", "register"]
        url_lower = ep.url.lower()

        is_sensitive = any(kw in url_lower for kw in sensitive_keywords)
        if not is_sensitive:
            return vulns

        # Check if sensitive flow is accessible without anti-automation controls
        captured = await self.client.request(ep.method, ep.url)
        if captured.status_code in (200, 201, 204):
            resp_headers = {k.lower(): v for k, v in captured.response_headers.items()}
            has_csrf = any("csrf" in k or "xsrf" in k for k in resp_headers)
            has_captcha = "captcha" in captured.response_body.lower() if captured.response_body else False

            if not has_csrf and not has_captcha:
                vulns.append(Vulnerability(
                    endpoint_id=ep.id, owasp_category="API6",
                    owasp_name=cat["name"],
                    title="Sensitive Flow Without Anti-Automation",
                    description="Sensitive business endpoint lacks CSRF protection and CAPTCHA.",
                    severity=RiskLevel.HIGH, status=VulnStatus.POTENTIAL,
                    risk_score=cat["base_score"],
                    poc_request=captured.format_request(),
                    poc_response=captured.format_response(),
                    poc_status_code=captured.status_code,
                    remediation="Add CAPTCHA, rate limiting, and anti-automation controls to sensitive flows.",
                    cwe_id="CWE-799",
                ))
        return vulns

    # ── API7: Server Side Request Forgery (SSRF) ──

    async def test_ssrf(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for SSRF by injecting internal URLs into parameters."""
        vulns = []
        cat = OWASP_CATEGORIES["API7"]

        if ep.method not in ("GET", "POST"):
            return vulns

        for payload in SSRF_PAYLOADS[:5]:
            # Test in query params
            captured = await self.client.request(
                ep.method, ep.url,
                params={"url": payload, "target": payload, "redirect": payload}
            )
            if captured.status_code in (200, 301, 302) and captured.status_code != 0:
                body = captured.response_body.lower() if captured.response_body else ""
                ssrf_indicators = ["root:", "localhost", "metadata", "ami-id",
                                   "instance-id", "internal", "private"]
                if any(ind in body for ind in ssrf_indicators):
                    vulns.append(Vulnerability(
                        endpoint_id=ep.id, owasp_category="API7",
                        owasp_name=cat["name"],
                        title=f"SSRF: Internal resource accessible via {payload[:30]}",
                        description="Server fetched an internal resource when given a crafted URL parameter.",
                        severity=RiskLevel.HIGH, status=VulnStatus.CONFIRMED,
                        risk_score=cat["base_score"],
                        poc_request=captured.format_request(),
                        poc_response=captured.format_response(),
                        poc_status_code=captured.status_code,
                        remediation="Validate and whitelist URLs. Block internal/private IPs.",
                        cwe_id="CWE-918",
                    ))
                    return vulns
        return vulns

    # ── API8: Security Misconfiguration ──

    async def test_security_misconfig(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for security misconfigurations in headers and responses."""
        vulns = []
        cat = OWASP_CATEGORIES["API8"]
        captured = await self.client.request(ep.method, ep.url)

        if captured.status_code == 0:
            return vulns

        resp_headers = {k.lower(): v for k, v in captured.response_headers.items()}

        # Check CORS misconfiguration
        cors_origin = resp_headers.get("access-control-allow-origin", "")
        if cors_origin == "*":
            vulns.append(Vulnerability(
                endpoint_id=ep.id, owasp_category="API8",
                owasp_name=cat["name"],
                title="CORS Misconfiguration: Wildcard Origin",
                description="Access-Control-Allow-Origin is set to '*', allowing any origin.",
                severity=RiskLevel.MEDIUM, status=VulnStatus.CONFIRMED,
                risk_score=6.0,
                remediation="Restrict CORS to specific trusted origins.",
                cwe_id="CWE-942",
            ))

        # Check missing security headers
        missing = []
        security_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY/SAMEORIGIN",
            "strict-transport-security": "HSTS",
        }
        for header, name in security_headers.items():
            if header not in resp_headers:
                missing.append(name)

        if missing:
            vulns.append(Vulnerability(
                endpoint_id=ep.id, owasp_category="API8",
                owasp_name=cat["name"],
                title=f"Missing Security Headers: {', '.join(missing[:3])}",
                description=f"Response is missing security headers: {', '.join(missing)}",
                severity=RiskLevel.LOW, status=VulnStatus.CONFIRMED,
                risk_score=4.0,
                remediation="Add standard security headers to all API responses.",
                cwe_id="CWE-693",
            ))

        # Check verbose error messages
        if captured.response_body:
            for pattern_name in ("stack_trace", "sql_error"):
                pattern = SENSITIVE_PATTERNS.get(pattern_name)
                if pattern and re.search(pattern, captured.response_body):
                    vulns.append(Vulnerability(
                        endpoint_id=ep.id, owasp_category="API8",
                        owasp_name=cat["name"],
                        title=f"Information Leak: {pattern_name.replace('_', ' ').title()}",
                        description=f"Response contains {pattern_name.replace('_', ' ')} information.",
                        severity=RiskLevel.MEDIUM, status=VulnStatus.CONFIRMED,
                        risk_score=6.5,
                        poc_response=captured.format_response(),
                        poc_status_code=captured.status_code,
                        remediation="Suppress detailed error messages in production. Use generic error responses.",
                        cwe_id="CWE-209",
                    ))

        # Check for auth bypass headers
        for bypass_headers in AUTH_BYPASS_HEADERS[:3]:
            bypass_captured = await self.client.request(
                ep.method, ep.url, headers=bypass_headers
            )
            if (bypass_captured.status_code in (200, 201) and
                    captured.status_code in (401, 403)):
                vulns.append(Vulnerability(
                    endpoint_id=ep.id, owasp_category="API8",
                    owasp_name=cat["name"],
                    title=f"Auth Bypass via Header: {list(bypass_headers.keys())[0]}",
                    description="Authentication bypassed using special HTTP headers.",
                    severity=RiskLevel.CRITICAL, status=VulnStatus.CONFIRMED,
                    risk_score=9.5,
                    poc_request=bypass_captured.format_request(),
                    poc_response=bypass_captured.format_response(),
                    remediation="Do not rely on client-supplied headers for authorization decisions.",
                    cwe_id="CWE-287",
                ))
                break
        return vulns

    # ── API9: Improper Inventory Management ──

    async def test_improper_inventory(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for improper API inventory — old versions, debug endpoints."""
        vulns = []
        cat = OWASP_CATEGORIES["API9"]

        if ep.is_shadow:
            vulns.append(Vulnerability(
                endpoint_id=ep.id, owasp_category="API9",
                owasp_name=cat["name"],
                title="Shadow API: Undocumented Endpoint",
                description=f"Endpoint {ep.url} is not documented in any API specification.",
                severity=RiskLevel.MEDIUM, status=VulnStatus.CONFIRMED,
                risk_score=cat["base_score"],
                remediation="Document all API endpoints. Remove deprecated/unused APIs.",
                cwe_id="CWE-1059",
            ))

        # Check for old API versions
        parsed = urlparse(ep.url)
        path = parsed.path
        version_match = re.search(r'/v(\d+)/', path)
        if version_match:
            current_ver = int(version_match.group(1))
            for old_ver in range(1, current_ver):
                old_path = path.replace(f"/v{current_ver}/", f"/v{old_ver}/")
                old_url = f"{parsed.scheme}://{parsed.netloc}{old_path}"
                captured = await self.client.request("GET", old_url)
                if captured.status_code in (200, 201) and captured.status_code != 0:
                    vulns.append(Vulnerability(
                        endpoint_id=ep.id, owasp_category="API9",
                        owasp_name=cat["name"],
                        title=f"Old API Version Active: v{old_ver}",
                        description=f"Old API version v{old_ver} is still accessible.",
                        severity=RiskLevel.MEDIUM, status=VulnStatus.CONFIRMED,
                        risk_score=6.5,
                        poc_request=captured.format_request(),
                        poc_response=captured.format_response(),
                        remediation="Deprecate and remove old API versions.",
                        cwe_id="CWE-1059",
                    ))
        return vulns

    # ── API10: Unsafe Consumption of APIs ──

    async def test_unsafe_consumption(self, ep: APIEndpoint) -> list[Vulnerability]:
        """Test for unsafe consumption of APIs — injection via parameters."""
        vulns = []
        cat = OWASP_CATEGORIES["API10"]

        fuzz_payloads = self.fuzzer.get_payloads("sql_injection")[:3]
        fuzz_payloads += self.fuzzer.get_payloads("xss")[:2]

        for payload in fuzz_payloads:
            captured = await self.client.request(
                ep.method, ep.url, params={"q": payload, "search": payload, "input": payload}
            )
            if captured.status_code == 0:
                continue

            body = captured.response_body.lower() if captured.response_body else ""
            # Check for SQL error indicators
            if any(ind in body for ind in ["sql", "syntax error", "mysql", "postgresql", "ora-"]):
                vulns.append(Vulnerability(
                    endpoint_id=ep.id, owasp_category="API10",
                    owasp_name=cat["name"],
                    title="SQL Injection Indicator in Response",
                    description=f"SQL error message detected when injecting: {payload[:30]}",
                    severity=RiskLevel.CRITICAL, status=VulnStatus.POTENTIAL,
                    risk_score=9.5,
                    poc_request=captured.format_request(),
                    poc_response=captured.format_response(),
                    remediation="Use parameterized queries. Validate and sanitize all inputs.",
                    cwe_id="CWE-89",
                ))
                break

            # Check for reflected XSS
            if payload in (captured.response_body or ""):
                vulns.append(Vulnerability(
                    endpoint_id=ep.id, owasp_category="API10",
                    owasp_name=cat["name"],
                    title="Reflected Input in Response (Potential XSS)",
                    description=f"Input payload was reflected in the response body.",
                    severity=RiskLevel.HIGH, status=VulnStatus.POTENTIAL,
                    risk_score=7.5,
                    poc_request=captured.format_request(),
                    poc_response=captured.format_response(),
                    remediation="Sanitize all output. Use Content-Type headers properly.",
                    cwe_id="CWE-79",
                ))
                break
        return vulns
