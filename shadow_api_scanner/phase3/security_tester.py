"""
Phase 3: Security Tester Orchestrator

Coordinates OWASP API Top 10 security tests against
all discovered shadow API endpoints.
"""

from __future__ import annotations

import asyncio
import logging

from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, ScanResult, Vulnerability
from shadow_api_scanner.phase3.fuzzer import Fuzzer
from shadow_api_scanner.phase3.owasp_tests import OWASPTestSuite
from shadow_api_scanner.utils.http_client import AsyncHTTPClient

logger = logging.getLogger("shadow_api_scanner")


class SecurityTester:
    """
    Phase 3 orchestrator: run OWASP security tests.

    Tests each shadow endpoint concurrently (bounded by semaphore)
    and collects all vulnerability findings.
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.fuzzer = Fuzzer(max_payloads_per_category=config.max_fuzz_payloads)

    async def run(
        self, endpoints: list[APIEndpoint], result: ScanResult
    ) -> list[Vulnerability]:
        """
        Execute Phase 3 security testing.

        Args:
            endpoints: Endpoints to test (typically shadow endpoints)
            result: ScanResult to populate

        Returns:
            List of discovered vulnerabilities
        """
        logger.info("=" * 60)
        logger.info("🔒 PHASE 3: Automated Security Testing (OWASP API Top 10)")
        logger.info("=" * 60)

        if not endpoints:
            logger.info("  No endpoints to test.")
            return []

        logger.info(f"  Testing {len(endpoints)} endpoints...")

        all_vulns: list[Vulnerability] = []
        semaphore = asyncio.Semaphore(self.config.max_concurrent_tests)

        async with AsyncHTTPClient(self.config) as client:
            suite = OWASPTestSuite(client, self.fuzzer)

            async def test_endpoint(ep: APIEndpoint):
                async with semaphore:
                    logger.info(f"  🧪 Testing: {ep.method} {ep.url}")
                    vulns = await suite.run_all(ep)
                    if vulns:
                        logger.info(f"    ⚠️  Found {len(vulns)} potential vulnerabilities")
                    return vulns

            tasks = [test_endpoint(ep) for ep in endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, list):
                    all_vulns.extend(r)
                elif isinstance(r, Exception):
                    logger.warning(f"  Test error: {r}")
                    result.errors.append(str(r))

            result.tests_executed = client.total_requests

        result.vulnerabilities = all_vulns

        # Summary
        logger.info(f"\n📊 Phase 3 Results:")
        logger.info(f"  Total requests sent: {result.tests_executed}")
        logger.info(f"  Vulnerabilities found: {len(all_vulns)}")

        severity_counts = {}
        for v in all_vulns:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
        for sev, count in sorted(severity_counts.items()):
            logger.info(f"    {sev}: {count}")

        return all_vulns
