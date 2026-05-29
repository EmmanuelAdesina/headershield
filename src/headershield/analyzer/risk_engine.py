"""
Judgment layer.
Takes extracted headers, applies rules, produces findings.
This is where audit credibility lives.
"""

from typing import Dict, List
from headershield.core.models.finding import Finding
from headershield.core.models.scan_result import ScanResult
from headershield.core.enums.severity import Severity
from headershield.core.enums.status import Status
from headershield.analyzer.header_rules import RULES
from headershield.scanner.headers import extract_security_headers


def analyze(url: str, raw_headers: Dict[str, str], metadata: Dict) -> ScanResult:
    """
    Analyze extracted security headers against defined rules.
    Returns structured ScanResult with findings.
    """
    extracted = extract_security_headers(raw_headers)
    findings = []
    
    for header_key, rule in RULES.items():
        value = extracted.get(header_key)
        
        if value is None:
            # Missing
            findings.append(Finding(
                url=url,
                header_name=rule.name,
                status=Status.MISSING,
                severity=rule.severity,
                risk_path=rule.risk_path,
                evidence=f"Header '{rule.name}' not present in HTTP response",
                recommendation=rule.recommendation,
                current_value=None,
                expected_value=rule.expected,
            ))
        elif not rule.check(value):
            # Misconfigured / weak
            findings.append(Finding(
                url=url,
                header_name=rule.name,
                status=Status.WEAK,
                severity=rule.severity,
                risk_path=rule.risk_path,
                evidence=f"Header present but misconfigured. Raw value: '{value}'",
                recommendation=rule.recommendation,
                current_value=value,
                expected_value=rule.expected,
            ))
        else:
            # Pass
            findings.append(Finding(
                url=url,
                header_name=rule.name,
                status=Status.PRESENT,
                severity=Severity.INFO,
                risk_path="No risk - header correctly configured",
                evidence=f"Header correctly configured. Value: '{value}'",
                recommendation="No action required",
                current_value=value,
                expected_value=rule.expected,
            ))
    
    return ScanResult(
        url=url,
        findings=findings,
        status_code=metadata.get("status_code", 0),
        final_url=metadata.get("final_url", url),
        response_time_ms=metadata.get("response_time_ms", 0),
        timestamp=metadata.get("timestamp", ""),
    )
