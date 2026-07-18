"""
tests.test_scanner
Unit tests for the v2 scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock
from headershield.scanner.headers import extract_security_headers, SECURITY_HEADERS
from headershield.scanner.http_client import fetch_headers
from headershield.core.enums.severity import Severity


class TestHeaderExtraction(unittest.TestCase):

    def test_security_headers_list_complete(self):
        """Ensure all expected security headers are defined."""
        expected_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "server",
        ]
        for h in expected_headers:
            self.assertIn(h, SECURITY_HEADERS)

    def test_extract_from_empty_merged(self):
        """Extracting from empty merged headers returns all None."""
        raw = {"merged_headers": {}}
        result = extract_security_headers(raw)
        for header in SECURITY_HEADERS:
            self.assertIn(header, result)
            self.assertIsNone(result[header])

    def test_extract_from_populated_merged(self):
        """Extracting from populated merged headers returns correct values."""
        raw = {
            "merged_headers": {
                "strict-transport-security": "max-age=31536000",
                "x-frame-options": "DENY",
                "server": "nginx",
            }
        }
        result = extract_security_headers(raw)
        self.assertEqual(result["strict-transport-security"], "max-age=31536000")
        self.assertEqual(result["x-frame-options"], "DENY")
        self.assertEqual(result["server"], "nginx")
        self.assertIsNone(result["content-security-policy"])
        self.assertIsNone(result["referrer-policy"])

    def test_extract_missing_merged_key(self):
        """Extracting when merged_headers key is missing returns all None."""
        raw = {}
        result = extract_security_headers(raw)
        for header in SECURITY_HEADERS:
            self.assertIsNone(result[header])


class TestSeverityEnum(unittest.TestCase):

    def test_severity_values(self):
        """Test severity enum values."""
        self.assertEqual(Severity.P0.value, "CRITICAL")
        self.assertEqual(Severity.P1.value, "HIGH")
        self.assertEqual(Severity.P2.value, "MEDIUM")
        self.assertEqual(Severity.P3.value, "LOW")
        self.assertEqual(Severity.INFO.value, "INFO")


if __name__ == "__main__":
    unittest.main()
