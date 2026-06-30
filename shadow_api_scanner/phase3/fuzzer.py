"""
Phase 3: Fuzzer

Generates malformed, boundary, and adversarial inputs for
fuzzing API endpoints during security testing.
"""

from __future__ import annotations

import random
import string
from typing import Any
from shadow_api_scanner.core.config import FUZZ_PAYLOADS


class Fuzzer:
    """
    Generates fuzz payloads for API parameter testing.

    Combines predefined payloads from config with dynamically
    generated boundary-value inputs.
    """

    def __init__(self, max_payloads_per_category: int = 5):
        self.max_per_cat = max_payloads_per_category

    def get_payloads(self, category: str) -> list[str]:
        """Get fuzz payloads for a specific category."""
        payloads = FUZZ_PAYLOADS.get(category, [])
        if len(payloads) > self.max_per_cat:
            return random.sample(payloads, self.max_per_cat)
        return payloads

    def get_all_payloads(self) -> list[str]:
        """Get a combined sample of all fuzz payload categories."""
        all_payloads = []
        for category in FUZZ_PAYLOADS:
            all_payloads.extend(self.get_payloads(category))
        return all_payloads

    def generate_id_variants(self, original_id: str = "1") -> list[str]:
        """Generate ID parameter variants for BOLA/IDOR testing."""
        variants = [
            "0",
            "1",
            "2",
            "100",
            "999",
            "9999",
            "-1",
            "0.5",
            "null",
            "undefined",
            "admin",
            "true",
            "../../etc/passwd",
            str(int(original_id) + 1) if original_id.isdigit() else "2",
            str(int(original_id) - 1) if original_id.isdigit() else "0",
        ]
        return variants

    def generate_auth_variants(self) -> list[dict]:
        """Generate authentication bypass header variants."""
        return [
            {},  # No auth header
            {"Authorization": ""},  # Empty
            {"Authorization": "Bearer "},  # Empty bearer
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer " + "A" * 50},  # Random token
            {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
            {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},  # admin:password
            {"Cookie": ""},  # Empty cookie
            {"Cookie": "session=; token="},
        ]

    def generate_method_variants(self) -> list[str]:
        """Generate HTTP method variants for function-level auth testing."""
        return ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

    def generate_content_types(self) -> list[str]:
        """Generate Content-Type variants."""
        return [
            "application/json",
            "application/xml",
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/html",
        ]

    def generate_random_string(self, length: int = 20) -> str:
        """Generate a random alphanumeric string."""
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_rate_limit_batch(self, count: int = 50) -> list[int]:
        """Generate a sequence of request indices for rate limit testing."""
        return list(range(count))
