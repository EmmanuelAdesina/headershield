"""
Domain model: a single security finding.
Immutable. Audit-grade.
"""

from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime
from headershield.core.enums.severity import Severity
from headershield.core.enums.status import Status


@dataclass(frozen=True)
class Finding:
    url: str
    header_name: str
    status: Status
    severity: Severity
    risk_path: str
    evidence: str
    recommendation: str
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "header_name": self.header_name,
            "status": self.status.value,
            "severity": self.severity.value,
            "risk_path": self.risk_path,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "timestamp": self.timestamp,
        }
