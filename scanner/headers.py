"""
Security header extraction.
Maps raw HTTP headers to normalized security header dict.
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


def extract_security_headers(raw_headers: Dict[str, str]) -> Dict[str, Optional[str]]:
    """
    Extract only security-relevant headers from raw response.
    Returns lowercase keys for consistent lookup.
    """
    normalized = {k.lower(): v for k, v in raw_headers.items()}
    return {h: normalized.get(h) for h in SECURITY_HEADERS}
