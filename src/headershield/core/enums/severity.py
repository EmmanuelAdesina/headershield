"""
Severity classification system.
P0 = Critical exploit path
P1 = High risk exposure
P2 = Medium hardening gap
P3 = Low / informational
"""

from enum import Enum


class Severity(Enum):
    P0 = "CRITICAL"
    P1 = "HIGH"
    P2 = "MEDIUM"
    P3 = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.P0: 0,
    Severity.P1: 1,
    Severity.P2: 2,
    Severity.P3: 3,
    Severity.INFO: 4,
}
