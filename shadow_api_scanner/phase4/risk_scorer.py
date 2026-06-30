"""
Phase 4: Risk Scorer

Calculates risk scores per endpoint and overall scan based on
OWASP category severity, exploit success, and data sensitivity.
"""

from __future__ import annotations

import logging
from shadow_api_scanner.core.config import OWASP_CATEGORIES, SEVERITY_LEVELS
from shadow_api_scanner.core.models import (
    APIEndpoint, ScanResult, Vulnerability, RiskLevel, VulnStatus,
)

logger = logging.getLogger("shadow_api_scanner")


class RiskScorer:
    """
    Compute risk scores for vulnerabilities and the overall scan.

    Scoring factors:
      1. OWASP category base score
      2. Exploit confirmation multiplier
      3. Sensitive data exposure bonus
      4. Shadow API penalty (undocumented = higher risk)
    """

    def score(self, result: ScanResult) -> ScanResult:
        """
        Calculate and assign risk scores to all vulnerabilities.

        Args:
            result: ScanResult with vulnerabilities populated

        Returns:
            Updated ScanResult with risk scores computed
        """
        logger.info("=" * 60)
        logger.info("📈 PHASE 4: Risk Scoring")
        logger.info("=" * 60)

        endpoint_map = {ep.id: ep for ep in result.all_endpoints}

        for vuln in result.vulnerabilities:
            vuln.risk_score = self._calculate_score(vuln, endpoint_map)
            vuln.severity = self._score_to_level(vuln.risk_score)

        # Sort vulnerabilities by risk score (highest first)
        result.vulnerabilities.sort(key=lambda v: v.risk_score, reverse=True)

        # Finalize summary stats
        result.finalize()

        logger.info(f"\n📊 Risk Scoring Results:")
        logger.info(f"  Overall Risk Score: {result.overall_risk_score:.1f}")
        logger.info(f"  Overall Risk Level: {result.overall_risk_level.value}")
        logger.info(f"  Critical: {result.critical_count}")
        logger.info(f"  High: {result.high_count}")
        logger.info(f"  Medium: {result.medium_count}")
        logger.info(f"  Low: {result.low_count}")

        return result

    def _calculate_score(
        self, vuln: Vulnerability, endpoint_map: dict[str, APIEndpoint]
    ) -> float:
        """Calculate risk score for a single vulnerability."""
        # Base score from OWASP category
        cat = OWASP_CATEGORIES.get(vuln.owasp_category, {})
        base = cat.get("base_score", 5.0)

        # Confirmation multiplier
        if vuln.status == VulnStatus.CONFIRMED:
            multiplier = 1.0
        elif vuln.status == VulnStatus.POTENTIAL:
            multiplier = 0.8
        else:
            multiplier = 0.5

        # Shadow API bonus
        ep = endpoint_map.get(vuln.endpoint_id)
        shadow_bonus = 0.5 if (ep and ep.is_shadow) else 0.0

        # PoC evidence bonus
        poc_bonus = 0.3 if vuln.poc_status_code and vuln.poc_status_code in (200, 201) else 0.0

        score = min(10.0, (base * multiplier) + shadow_bonus + poc_bonus)
        return round(score, 1)

    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 9.0:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.INFO
