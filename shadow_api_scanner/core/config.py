"""
Global configuration and constants for Shadow API Scanner.

Centralizes all tunable settings, OWASP category definitions,
severity mappings, and default scan parameters.
"""

import os
import platform
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────────────────────
# OWASP API Security Top 10 (2023) Categories
# ──────────────────────────────────────────────────────────────

OWASP_CATEGORIES = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization (BOLA)",
        "severity": "Critical",
        "description": "APIs exposing endpoints that handle object identifiers, "
                       "creating a wide attack surface for object-level access control.",
        "base_score": 9.0,
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "severity": "Critical",
        "description": "Authentication mechanisms implemented incorrectly, "
                       "allowing attackers to compromise authentication tokens.",
        "base_score": 9.0,
    },
    "API3": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "severity": "High",
        "description": "Lack of or improper authorization validation at the "
                       "object property level.",
        "base_score": 7.5,
    },
    "API4": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "severity": "High",
        "description": "API requests consume resources such as network bandwidth, "
                       "CPU, memory, and storage without any restrictions.",
        "base_score": 7.0,
    },
    "API5": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "severity": "Critical",
        "description": "Complex access control policies with different hierarchies, "
                       "groups, and roles creating authorization flaws.",
        "base_score": 8.5,
    },
    "API6": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "severity": "High",
        "description": "APIs exposing business flows without compensating for "
                       "the risk of automated access.",
        "base_score": 7.0,
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery (SSRF)",
        "severity": "High",
        "description": "SSRF flaws occur when an API fetches a remote resource "
                       "without validating the user-supplied URI.",
        "base_score": 8.0,
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "severity": "Medium",
        "description": "APIs and supporting systems typically contain complex "
                       "configurations that can be misconfigured.",
        "base_score": 6.5,
    },
    "API9": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "severity": "Medium",
        "description": "APIs tend to expose more endpoints than traditional web "
                       "applications, making proper documentation important.",
        "base_score": 6.0,
    },
    "API10": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "severity": "Medium",
        "description": "Developers tend to trust data received from third-party "
                       "APIs without proper validation.",
        "base_score": 6.0,
    },
}

# ──────────────────────────────────────────────────────────────
# Severity → Numeric Ranges
# ──────────────────────────────────────────────────────────────

SEVERITY_LEVELS = {
    "Critical": {"min": 9.0, "max": 10.0, "color": "#DC2626"},
    "High": {"min": 7.0, "max": 8.9, "color": "#EA580C"},
    "Medium": {"min": 4.0, "max": 6.9, "color": "#CA8A04"},
    "Low": {"min": 0.1, "max": 3.9, "color": "#16A34A"},
    "Info": {"min": 0.0, "max": 0.0, "color": "#2563EB"},
}

# ──────────────────────────────────────────────────────────────
# SSRF Payloads
# ──────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",  # Azure / DigitalOcean
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "file:///etc/passwd",
    "file:///c:/windows/system32/drivers/etc/hosts",
]

# ──────────────────────────────────────────────────────────────
# Fuzzing Payloads
# ──────────────────────────────────────────────────────────────

FUZZ_PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1; DROP TABLE users--",
        "1 UNION SELECT null,null,null--",
        "admin'--",
        "') OR ('1'='1",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'\"><img src=x onerror=alert(1)>",
    ],
    "path_traversal": [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
    ],
    "command_injection": [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
    ],
    "integer_overflow": [
        "0",
        "-1",
        "99999999999999",
        "2147483647",
        "-2147483648",
    ],
    "format_string": [
        "%s%s%s%s%s",
        "%x%x%x%x",
        "{0}",
        "${7*7}",
    ],
    "special_chars": [
        "",
        "null",
        "undefined",
        "NaN",
        "true",
        "false",
        "[]",
        "{}",
        "{{}}",
    ],
}

# ──────────────────────────────────────────────────────────────
# Auth Bypass Headers
# ──────────────────────────────────────────────────────────────

AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Remote-Addr": "127.0.0.1"},
]

# ──────────────────────────────────────────────────────────────
# Sensitive Data Patterns (for response analysis)
# ──────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "jwt_token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "password_field": r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "phone": r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "internal_ip": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "stack_trace": r"(?i)(traceback|stack\s*trace|exception|error\s+at\s+line)",
    "sql_error": r"(?i)(sql\s*syntax|mysql|postgresql|sqlite|ora-\d+|unclosed\s+quotation)",
}


# ──────────────────────────────────────────────────────────────
# Scan Configuration Dataclass
# ──────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """Configuration for a single scan run."""

    target_url: str
    output_dir: str = "reports"
    openapi_spec_url: Optional[str] = None
    openapi_spec_file: Optional[str] = None

    # Phase 1 settings
    max_js_files: int = 200
    js_download_timeout: int = 30  # seconds per file
    crawl_depth: int = 3

    # Phase 2 settings
    browser_timeout: int = 60  # seconds for dynamic monitoring
    browser_headless: bool = True
    wait_after_load: int = 10  # seconds to wait after page load for XHR

    # Phase 3 settings
    max_concurrent_tests: int = 10
    request_timeout: int = 15  # seconds per request
    rate_limit_delay: float = 0.5  # seconds between requests
    enable_fuzzing: bool = True
    enable_ssrf_test: bool = True
    max_fuzz_payloads: int = 5  # per category

    # Phase 4 settings
    report_formats: list = field(default_factory=lambda: ["json", "html"])
    include_poc: bool = True  # include proof-of-concept in report

    # General
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    verbose: bool = False
    auth_token: Optional[str] = None
    auth_header: str = "Authorization"
    custom_headers: dict = field(default_factory=dict)

    @property
    def is_windows(self) -> bool:
        return platform.system() == "Windows"

    @property
    def is_linux(self) -> bool:
        return platform.system() == "Linux"

    def get_headers(self) -> dict:
        """Build default request headers."""
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.auth_token:
            headers[self.auth_header] = self.auth_token
        headers.update(self.custom_headers)
        return headers
