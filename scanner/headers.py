"""
headershield.scanner.headers
Core security header checks with risk path mapping.
"""

import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import time


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskPath(Enum):
    XSS_INJECTION = "XSS injection surface possible"
    CLICKJACKING = "Clickjacking attack possible"
    SSL_STRIPPING = "SSL stripping / downgrade attack possible"
    MIME_SNIFFING = "MIME type sniffing attack possible"
    SESSION_LEAKAGE = "Session data leakage via referrer"
    INFO_DISCLOSURE = "Information disclosure via server metadata"
    FEATURE_ABUSE = "Unwanted browser feature abuse possible"
    CSRF_WEAKNESS = "CSRF protection weakness"


@dataclass
class HeaderFinding:
    header_name: str
    present: bool
    value: Optional[str]
    expected: str
    severity: Severity
    risk_paths: List[RiskPath] = field(default_factory=list)
    remediation: str = ""
    evidence: str = ""


# Security header definitions with risk mapping
HEADER_RULES = {
    "Strict-Transport-Security": {
        "severity": Severity.CRITICAL,
        "risk_paths": [RiskPath.SSL_STRIPPING],
        "check": lambda v: v is not None and "max-age" in v.lower(),
        "expected": "max-age=31536000; includeSubDomains",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": Severity.CRITICAL,
        "risk_paths": [RiskPath.XSS_INJECTION],
        "check": lambda v: v is not None and len(v) > 10,
        "expected": "default-src 'self'; script-src 'self'",
        "remediation": "Add a strict CSP policy. Start with: default-src 'self'; script-src 'self'; object-src 'none'",
    },
    "X-Frame-Options": {
        "severity": Severity.HIGH,
        "risk_paths": [RiskPath.CLICKJACKING],
        "check": lambda v: v is not None and v.upper() in ["DENY", "SAMEORIGIN"],
        "expected": "DENY or SAMEORIGIN",
        "remediation": "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": Severity.HIGH,
        "risk_paths": [RiskPath.MIME_SNIFFING],
        "check": lambda v: v is not None and v.lower() == "nosniff",
        "expected": "nosniff",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": Severity.MEDIUM,
        "risk_paths": [RiskPath.SESSION_LEAKAGE],
        "check": lambda v: v is not None and v.lower() in ["no-referrer", "strict-origin-when-cross-origin", "same-origin"],
        "expected": "strict-origin-when-cross-origin or no-referrer",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": Severity.MEDIUM,
        "risk_paths": [RiskPath.FEATURE_ABUSE],
        "check": lambda v: v is not None and len(v) > 5,
        "expected": "geolocation=(), microphone=(), camera=()",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "X-Content-Type-Options": {
        "severity": Severity.HIGH,
        "risk_paths": [RiskPath.MIME_SNIFFING],
        "check": lambda v: v is not None and v.lower() == "nosniff",
        "expected": "nosniff",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Server": {
        "severity": Severity.LOW,
        "risk_paths": [RiskPath.INFO_DISCLOSURE],
        "check": lambda v: v is None or v.strip() == "" or v.lower() in ["hidden", "concealed"],
        "expected": "Hidden or minimal version info",
        "remediation": "Remove or minimize Server header. Use: Server: webserver or strip entirely",
    },
}

# Fix duplicate key
HEADER_RULES.pop("X-Content-Type-Options", None)
HEADER_RULES["X-Content-Type-Options"] = {
    "severity": Severity.HIGH,
    "risk_paths": [RiskPath.MIME_SNIFFING],
    "check": lambda v: v is not None and v.lower() == "nosniff",
    "expected": "nosniff",
    "remediation": "Add: X-Content-Type-Options: nosniff",
}


def scan_url(url: str, timeout: int = 10, verify_ssl: bool = True) -> Dict:
    """
    Scan a single URL for security headers.
    Returns structured findings with evidence.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    start_time = time.time()

    try:
        response = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        response.raise_for_status()
    except requests.exceptions.SSLError:
        # Try HTTP fallback for SSL issues
        url = url.replace("https://", "http://")
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "findings": [],
        }

    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []

    for header_name, rules in HEADER_RULES.items():
        header_value = headers.get(header_name.lower())
        present = header_value is not None
        valid = rules["check"](header_value) if present else False

        # Determine severity: if missing or invalid, use rule severity
        if not present or not valid:
            severity = rules["severity"]
        else:
            severity = Severity.INFO

        finding = HeaderFinding(
            header_name=header_name,
            present=present,
            value=header_value,
            expected=rules["expected"],
            severity=severity,
            risk_paths=rules["risk_paths"] if not valid else [],
            remediation=rules["remediation"] if not valid else "Header is correctly configured",
            evidence=f"Raw value: {header_value}" if present else "Header not present in response",
        )
        findings.append(finding)

    elapsed = round(time.time() - start_time, 3)

    return {
        "url": url,
        "status_code": response.status_code,
        "final_url": response.url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "response_time_ms": elapsed * 1000,
        "findings": findings,
    }


def get_risk_summary(findings: List[HeaderFinding]) -> Dict:
    """Summarize risk paths from findings."""
    risk_paths = {}
    severity_count = {s: 0 for s in Severity}

    for f in findings:
        severity_count[f.severity] += 1
        for rp in f.risk_paths:
            risk_paths[rp.value] = risk_paths.get(rp.value, 0) + 1

    return {
        "severity_count": {k.value: v for k, v in severity_count.items()},
        "active_risk_paths": risk_paths,
        "total_issues": sum(1 for f in findings if f.severity != Severity.INFO),
    }
