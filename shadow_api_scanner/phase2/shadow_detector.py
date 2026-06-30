"""
Phase 2: Shadow API Detector

Merges static and dynamic findings, compares against documented APIs,
and identifies shadow (undocumented) endpoints.
"""

from __future__ import annotations

import logging
from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import APIEndpoint, ScanResult
from shadow_api_scanner.phase2.traffic_monitor import TrafficMonitor
from shadow_api_scanner.phase2.spec_comparator import SpecComparator
from shadow_api_scanner.utils.helpers import normalize_url

logger = logging.getLogger("shadow_api_scanner")


class ShadowDetector:
    """
    Phase 2 orchestrator: merge inventories and detect shadow APIs.

    1. Run dynamic traffic monitoring
    2. Discover/parse OpenAPI spec
    3. Merge static + dynamic findings
    4. Classify endpoints as documented or shadow
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.spec_comparator = SpecComparator(config)

    async def run(
        self, static_endpoints: list[APIEndpoint], result: ScanResult
    ) -> list[APIEndpoint]:
        """
        Execute Phase 2: dynamic monitoring + shadow detection.

        Args:
            static_endpoints: Endpoints from Phase 1
            result: ScanResult to populate

        Returns:
            List of all endpoints with shadow flag set
        """
        # Step 1: Dynamic traffic monitoring
        monitor = TrafficMonitor(self.config)
        dynamic_endpoints = await monitor.run()
        result.dynamic_endpoints = dynamic_endpoints
        result.traffic_requests_captured = len(dynamic_endpoints)

        # Step 2: Discover/parse OpenAPI spec
        documented_endpoints = await self.spec_comparator.discover_and_parse()
        if documented_endpoints:
            result.openapi_spec_found = True
            result.documented_endpoints = documented_endpoints

        # Step 3: Merge all findings
        all_endpoints = self._merge_endpoints(
            static_endpoints, dynamic_endpoints, documented_endpoints
        )

        # Step 4: Classify shadow vs documented
        shadow_count = 0
        for ep in all_endpoints:
            if result.openapi_spec_found:
                if not self.spec_comparator.is_documented(ep):
                    ep.is_shadow = True
                    shadow_count += 1
            else:
                # No spec available — all non-trivial endpoints are potentially shadow
                ep.is_shadow = True
                shadow_count += 1

        result.all_endpoints = all_endpoints
        result.shadow_endpoints = [ep for ep in all_endpoints if ep.is_shadow]

        logger.info(f"\n📊 Shadow Detection Results:")
        logger.info(f"  Total unique endpoints: {len(all_endpoints)}")
        logger.info(f"  Shadow (undocumented): {shadow_count}")
        logger.info(f"  Documented: {len(all_endpoints) - shadow_count}")
        logger.info(f"  OpenAPI spec found: {result.openapi_spec_found}")

        if result.shadow_endpoints:
            logger.info("\n  🔴 Shadow APIs identified:")
            for ep in result.shadow_endpoints:
                logger.info(f"    {ep.method:6s} {ep.url}")

        return all_endpoints

    def _merge_endpoints(
        self,
        static: list[APIEndpoint],
        dynamic: list[APIEndpoint],
        documented: list[APIEndpoint],
    ) -> list[APIEndpoint]:
        """
        Merge endpoints from all sources, deduplicating by normalized URL + method.
        Dynamic findings take priority (they have response data).
        """
        merged: dict[tuple[str, str], APIEndpoint] = {}

        # Add documented first (lowest priority)
        for ep in documented:
            key = (normalize_url(ep.url), ep.method)
            merged[key] = ep

        # Add static (medium priority)
        for ep in static:
            key = (normalize_url(ep.url), ep.method)
            if key not in merged:
                merged[key] = ep

        # Add dynamic (highest priority — has real response data)
        for ep in dynamic:
            key = (normalize_url(ep.url), ep.method)
            merged[key] = ep  # Override with dynamic data

        return list(merged.values())
