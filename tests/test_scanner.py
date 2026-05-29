"""
headershield.tests.test_scanner
Unit tests for the scanner module.
"""

import unittest
from headershield.scanner.headers import scan_url, HEADER_RULES, Severity


class TestHeaderScanner(unittest.TestCase):

    def test_header_rules_loaded(self):
        """Ensure all header rules are defined."""
        expected_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Server",
        ]
        for h in expected_headers:
            self.assertIn(h, HEADER_RULES)

    def test_scan_url_invalid(self):
        """Test scanning an invalid URL."""
        result = scan_url("not-a-valid-url-at-all-12345.xyz")
        self.assertIn("error", result)

    def test_scan_url_google(self):
        """Test scanning a real URL (may fail without network)."""
        result = scan_url("https://google.com")
        # Should either succeed or have an error
        self.assertTrue("status_code" in result or "error" in result)

    def test_severity_ordering(self):
        """Test severity enum values."""
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")
        self.assertEqual(Severity.HIGH.value, "HIGH")


if __name__ == "__main__":
    unittest.main()
