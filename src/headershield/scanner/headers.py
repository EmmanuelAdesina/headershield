"""
Security header extraction.
Uses merged headers from redirect chain for accurate evaluation.
"""

from typing import Dict, Optional


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "server",
]


def extract_security_headers(raw_response: Dict) -> Dict[str, Optional[str]]:
    """
    Extract security headers from merged redirect chain headers.
    This ensures HSTS from intermediate hops is captured.
    """
    merged = raw_response.get("merged_headers", {})
    return {h: merged.get(h) for h in SECURITY_HEADERS}
