"""
Source of truth for header security rules.
Every rule defines: what to check, what severity, what risk, what fix.
"""

from headershield.core.enums.severity import Severity


class HeaderRule:
    def __init__(self, name: str, severity: Severity, risk_path: str, 
                 check_func, recommendation: str, expected: str):
        self.name = name
        self.severity = severity
        self.risk_path = risk_path
        self.check = check_func
        self.recommendation = recommendation
        self.expected = expected


RULES = {
    "strict-transport-security": HeaderRule(
        name="Strict-Transport-Security",
        severity=Severity.P0,
        risk_path="SSL stripping / downgrade attack possible",
        check_func=lambda v: v is not None and "max-age" in v.lower(),
        recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        expected="max-age=31536000; includeSubDomains",
    ),
    "content-security-policy": HeaderRule(
        name="Content-Security-Policy",
        severity=Severity.P0,
        risk_path="XSS injection surface possible",
        check_func=lambda v: v is not None and len(v) > 10,
        recommendation="Add a strict CSP. Start with: default-src 'self'; script-src 'self'; object-src 'none'",
        expected="default-src 'self'; script-src 'self'",
    ),
    "x-frame-options": HeaderRule(
        name="X-Frame-Options",
        severity=Severity.P1,
        risk_path="Clickjacking attack possible",
        check_func=lambda v: v is not None and v.upper() in ["DENY", "SAMEORIGIN"],
        recommendation="Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
        expected="DENY or SAMEORIGIN",
    ),
    "x-content-type-options": HeaderRule(
        name="X-Content-Type-Options",
        severity=Severity.P1,
        risk_path="MIME sniffing attack possible",
        check_func=lambda v: v is not None and v.lower() == "nosniff",
        recommendation="Add: X-Content-Type-Options: nosniff",
        expected="nosniff",
    ),
    "referrer-policy": HeaderRule(
        name="Referrer-Policy",
        severity=Severity.P2,
        risk_path="Session data leakage via referrer",
        check_func=lambda v: v is not None and v.lower() in ["no-referrer", "strict-origin-when-cross-origin", "same-origin"],
        recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
        expected="strict-origin-when-cross-origin or no-referrer",
    ),
    "permissions-policy": HeaderRule(
        name="Permissions-Policy",
        severity=Severity.P2,
        risk_path="Unwanted browser feature abuse possible",
        check_func=lambda v: v is not None and len(v) > 5,
        recommendation="Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        expected="geolocation=(), microphone=(), camera=()",
    ),
    "server": HeaderRule(
        name="Server",
        severity=Severity.P3,
        risk_path="Information disclosure via server metadata",
        check_func=lambda v: v is None or v.strip() == "" or v.lower() in ["hidden", "concealed"],
        recommendation="Remove or minimize Server header. Use: Server: webserver or strip entirely",
        expected="Hidden or minimal",
    ),
}
