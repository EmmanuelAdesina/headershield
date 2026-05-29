"""
Judgment layer with confidence scoring and measured risk calibration.
"""

from typing import Dict, List
from headershield.core.models.finding import Finding
from headershield.core.models.scan_result import ScanResult
from headershield.core.enums.severity import Severity
from headershield.core.enums.status import Status
from headershield.analyzer.header_rules import RULES
from headershield.scanner.headers import extract_security_headers


def _calculate_confidence(header_name: str, raw_response: Dict, status: Status) -> str:
    """
    Calculate confidence level for a finding.
    
    High: Direct scan, no redirects, header clearly present or absent.
    Medium: Redirect chain detected, merged headers used, or ambiguous value.
    Low: Error during scan, SSL issues, or incomplete response.
    """
    if "error" in raw_response and raw_response["error"]:
        return "LOW"
    
    redirect_count = raw_response.get("redirect_count", 0)
    
    if redirect_count > 0:
        if status == Status.MISSING:
            # Missing after redirects: could be on intermediate hop
            return "MEDIUM"
        elif status == Status.PRESENT:
            # Present after merge: high confidence
            return "HIGH"
        else:
            return "MEDIUM"
    
    # No redirects
    if status in (Status.MISSING, Status.PRESENT):
        return "HIGH"
    
    return "MEDIUM"


def _calibrate_severity(rule_severity: Severity, confidence: str, redirect_count: int) -> Severity:
    """
    Calibrate severity based on confidence and redirect context.
    
    - If redirect chain exists and header is missing: downgrade by one level
      (may exist on intermediate hop not captured)
    - If confidence is LOW: downgrade by one level
    - Never upgrade severity
    """
    if confidence == "LOW":
        downgrade_map = {
            Severity.P0: Severity.P1,
            Severity.P1: Severity.P2,
            Severity.P2: Severity.P3,
            Severity.P3: Severity.P3,
            Severity.INFO: Severity.INFO,
        }
        return downgrade_map.get(rule_severity, rule_severity)
    
    if redirect_count > 0 and rule_severity in (Severity.P0, Severity.P1):
        # Redirect chains create ambiguity for strict headers
        downgrade_map = {
            Severity.P0: Severity.P1,
            Severity.P1: Severity.P2,
            Severity.P2: Severity.P2,
            Severity.P3: Severity.P3,
            Severity.INFO: Severity.INFO,
        }
        return downgrade_map.get(rule_severity, rule_severity)
    
    return rule_severity


def analyze(url: str, raw_response: Dict, metadata: Dict) -> ScanResult:
    """
    Analyze extracted security headers against defined rules.
    Uses merged headers from redirect chain and applies confidence scoring.
    """
    extracted = extract_security_headers(raw_response)
    findings = []
    redirect_count = raw_response.get("redirect_count", 0)
    
    for header_key, rule in RULES.items():
        value = extracted.get(header_key)
        
        if value is None:
            status = Status.MISSING
            confidence = _calculate_confidence(rule.name, raw_response, status)
            severity = _calibrate_severity(rule.severity, confidence, redirect_count)
            
            if redirect_count > 0:
                evidence = f"Header '{rule.name}' not found in final response. {redirect_count} redirect(s) detected; header may exist on intermediate hop."
            else:
                evidence = f"Header '{rule.name}' not present in HTTP response."
            
            findings.append(Finding(
                url=url,
                header_name=rule.name,
                status=status,
                severity=severity,
                risk_path=rule.risk_path,
                evidence=evidence,
                recommendation=rule.recommendation,
                current_value=None,
                expected_value=rule.expected,
            ))
        elif not rule.check(value):
            status = Status.WEAK
            confidence = _calculate_confidence(rule.name, raw_response, status)
            severity = _calibrate_severity(rule.severity, confidence, redirect_count)
            
            findings.append(Finding(
                url=url,
                header_name=rule.name,
                status=status,
                severity=severity,
                risk_path=rule.risk_path,
                evidence=f"Header present but misconfigured. Confidence: {confidence}. Raw value: '{value}'",
                recommendation=rule.recommendation,
                current_value=value,
                expected_value=rule.expected,
            ))
        else:
            status = Status.PRESENT
            confidence = _calculate_confidence(rule.name, raw_response, status)
            
            findings.append(Finding(
                url=url,
                header_name=rule.name,
                status=status,
                severity=Severity.INFO,
                risk_path="No risk — header correctly configured",
                evidence=f"Header correctly configured. Confidence: {confidence}. Value: '{value}'",
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
