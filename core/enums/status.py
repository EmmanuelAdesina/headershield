"""
Finding status definitions.
"""

from enum import Enum


class Status(Enum):
    MISSING = "missing"
    MISCONFIGURED = "misconfigured"
    PRESENT = "present"
    WEAK = "weak"
