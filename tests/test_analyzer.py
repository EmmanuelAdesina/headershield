"""
Tests for the analyzer layer.
"""

import unittest
from headershield.analyzer.header_rules import RULES
from headershield.core.enums.severity import Severity


class TestHeaderRules(unittest.TestCase):

    def test_all_rules_have_required_fields(self):
        for key, rule in RULES.items():
            self.assertIsNotNone(rule.name)
            self.assertIsNotNone(rule.severity)
            self.assertIsNotNone(rule.risk_path)
            self.assertIsNotNone(rule.check)
            self.assertIsNotNone(rule.recommendation)
            self.assertIsNotNone(rule.expected)

    def test_hsts_missing_detected(self):
        rule = RULES["strict-transport-security"]
        self.assertFalse(rule.check(None))
        self.assertTrue(rule.check("max-age=31536000"))

    def test_csp_weak_detected(self):
        rule = RULES["content-security-policy"]
        self.assertFalse(rule.check(""))
        self.assertTrue(rule.check("default-src 'self'"))


if __name__ == "__main__":
    unittest.main()
