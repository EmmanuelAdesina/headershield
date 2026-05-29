"""
Domain model: complete scan result for a single target.
"""

from dataclasses import dataclass, field
from typing import List
from headershield.core.models.finding import Finding
from headershield.core.enums.severity import Severity, SEVERITY_ORDER


@dataclass
class ScanResult:
    url: str
    findings: List[Finding]
    status_code: int = 0
    final_url: str = ""
    response_time_ms: float = 0.0
    timestamp: str = ""

    def severity_score(self) -> int:
        """Deterministic scoring: lower is better (0 = perfect)."""
        return sum(
            SEVERITY_ORDER.get(f.severity, 99) 
            for f in self.findings 
            if f.severity != Severity.INFO
        )

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.P0)

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.P1)

    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.P2)

    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.P3)

    def total_issues(self) -> int:
        return sum(1 for f in self.findings if f.severity != Severity.INFO)

    def active_risk_paths(self) -> dict:
        paths = {}
        for f in self.findings:
            if f.severity != Severity.INFO:
                paths[f.risk_path] = paths.get(f.risk_path, 0) + 1
        return paths

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "timestamp": self.timestamp,
            "severity_score": self.severity_score(),
            "issue_counts": {
                "critical": self.critical_count(),
                "high": self.high_count(),
                "medium": self.medium_count(),
                "low": self.low_count(),
                "total": self.total_issues(),
            },
            "active_risk_paths": self.active_risk_paths(),
            "findings": [f.to_dict() for f in self.findings],
        }
