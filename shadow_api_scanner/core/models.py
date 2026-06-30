"""
Data models for Shadow API Scanner.

Defines the core dataclasses used across all four phases:
endpoints, vulnerabilities, findings, and scan results.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class EndpointSource(str, Enum):
    """Where an endpoint was discovered."""
    STATIC_JS = "static_js_analysis"
    DYNAMIC_TRAFFIC = "dynamic_traffic_capture"
    OPENAPI_SPEC = "openapi_specification"
    MANUAL = "manual_entry"


class EndpointType(str, Enum):
    """Type of API endpoint."""
    REST = "REST"
    GRAPHQL = "GraphQL"
    WEBSOCKET = "WebSocket"
    GRPC = "gRPC"
    UNKNOWN = "Unknown"


class RiskLevel(str, Enum):
    """Risk classification."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class VulnStatus(str, Enum):
    """Vulnerability status."""
    CONFIRMED = "Confirmed"
    POTENTIAL = "Potential"
    FALSE_POSITIVE = "False Positive"
    NOT_TESTED = "Not Tested"


# ──────────────────────────────────────────────────────────────
# Discovered API Endpoint
# ──────────────────────────────────────────────────────────────

@dataclass
class APIEndpoint:
    """Represents a single discovered API endpoint."""

    url: str
    method: str = "GET"
    endpoint_type: EndpointType = EndpointType.REST
    source: EndpointSource = EndpointSource.STATIC_JS
    is_shadow: bool = False

    # Request details captured during discovery
    headers: dict = field(default_factory=dict)
    query_params: dict = field(default_factory=dict)
    body_params: dict = field(default_factory=dict)
    content_type: Optional[str] = None

    # Response details (from dynamic capture)
    status_code: Optional[int] = None
    response_headers: dict = field(default_factory=dict)
    response_body: Optional[str] = None
    response_size: Optional[int] = None

    # Metadata
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    js_file_source: Optional[str] = None  # which JS file it was found in
    confidence: float = 1.0  # 0.0 → 1.0, how confident we are this is a real endpoint

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    @property
    def normalized_url(self) -> str:
        """Return URL without query string for deduplication."""
        return self.url.split("?")[0].rstrip("/")

    def __hash__(self):
        return hash((self.normalized_url, self.method))

    def __eq__(self, other):
        if not isinstance(other, APIEndpoint):
            return False
        return (self.normalized_url == other.normalized_url and
                self.method == other.method)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "url": self.url,
            "method": self.method,
            "type": self.endpoint_type.value,
            "source": self.source.value,
            "is_shadow": self.is_shadow,
            "status_code": self.status_code,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at,
            "js_file_source": self.js_file_source,
        }


# ──────────────────────────────────────────────────────────────
# Vulnerability Finding
# ──────────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """A single security vulnerability found on an endpoint."""

    endpoint_id: str
    owasp_category: str  # e.g., "API1"
    owasp_name: str
    title: str
    description: str
    severity: RiskLevel = RiskLevel.MEDIUM
    status: VulnStatus = VulnStatus.POTENTIAL
    risk_score: float = 5.0

    # Proof of concept
    poc_request: Optional[str] = None
    poc_response: Optional[str] = None
    poc_status_code: Optional[int] = None
    poc_evidence: Optional[str] = None

    # Remediation
    remediation: str = ""
    cwe_id: Optional[str] = None
    references: list = field(default_factory=list)

    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    found_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "endpoint_id": self.endpoint_id,
            "owasp_category": self.owasp_category,
            "owasp_name": self.owasp_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "risk_score": self.risk_score,
            "poc_request": self.poc_request,
            "poc_response": self.poc_response,
            "poc_status_code": self.poc_status_code,
            "poc_evidence": self.poc_evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "references": self.references,
            "found_at": self.found_at,
        }


# ──────────────────────────────────────────────────────────────
# Scan Result (Aggregate)
# ──────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Aggregate result of a complete scan run."""

    target_url: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None

    # Phase 1 — static analysis results
    js_files_analyzed: int = 0
    static_endpoints: list[APIEndpoint] = field(default_factory=list)

    # Phase 2 — dynamic capture results
    dynamic_endpoints: list[APIEndpoint] = field(default_factory=list)
    traffic_requests_captured: int = 0

    # Merged inventory & shadow detection
    all_endpoints: list[APIEndpoint] = field(default_factory=list)
    shadow_endpoints: list[APIEndpoint] = field(default_factory=list)
    documented_endpoints: list[APIEndpoint] = field(default_factory=list)
    openapi_spec_found: bool = False

    # Phase 3 — security testing results
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    tests_executed: int = 0

    # Phase 4 — risk summary
    overall_risk_score: float = 0.0
    overall_risk_level: RiskLevel = RiskLevel.INFO
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Errors / warnings during scan
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def finalize(self):
        """Compute summary statistics after scan completes."""
        self.completed_at = datetime.utcnow().isoformat()
        self.critical_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.CRITICAL
        )
        self.high_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.HIGH
        )
        self.medium_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.MEDIUM
        )
        self.low_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.LOW
        )
        self.info_count = sum(
            1 for v in self.vulnerabilities if v.severity == RiskLevel.INFO
        )

        if self.vulnerabilities:
            self.overall_risk_score = max(v.risk_score for v in self.vulnerabilities)
        else:
            self.overall_risk_score = 0.0

        if self.overall_risk_score >= 9.0:
            self.overall_risk_level = RiskLevel.CRITICAL
        elif self.overall_risk_score >= 7.0:
            self.overall_risk_level = RiskLevel.HIGH
        elif self.overall_risk_score >= 4.0:
            self.overall_risk_level = RiskLevel.MEDIUM
        elif self.overall_risk_score > 0:
            self.overall_risk_level = RiskLevel.LOW
        else:
            self.overall_risk_level = RiskLevel.INFO

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "summary": {
                "js_files_analyzed": self.js_files_analyzed,
                "total_endpoints_discovered": len(self.all_endpoints),
                "shadow_endpoints": len(self.shadow_endpoints),
                "documented_endpoints": len(self.documented_endpoints),
                "traffic_requests_captured": self.traffic_requests_captured,
                "openapi_spec_found": self.openapi_spec_found,
                "tests_executed": self.tests_executed,
                "vulnerabilities_found": len(self.vulnerabilities),
                "overall_risk_score": self.overall_risk_score,
                "overall_risk_level": self.overall_risk_level.value,
                "severity_breakdown": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                    "info": self.info_count,
                },
            },
            "endpoints": {
                "all": [e.to_dict() for e in self.all_endpoints],
                "shadow": [e.to_dict() for e in self.shadow_endpoints],
                "documented": [e.to_dict() for e in self.documented_endpoints],
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "errors": self.errors,
            "warnings": self.warnings,
        }
