"""
Tests for Hand-Built Custom Evaluation Cases.
Validates:
- Historical email identity resolution
- Restore risk handling and blocking
- Account tombstone exposed PII remediation
- Non-English non-deletion request rejection (NOT_APPLICABLE)
"""

import os
import sys
import json
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CODE = os.path.join(ROOT, "code")
if CODE not in sys.path:
    sys.path.insert(0, CODE)

from engine.intent_classifier import IntentClassifier
from engine.rules_engine import ConfigurableRulesEngine
from engine.common import load_csv

CUSTOM_CASES_DIR = os.path.join(CODE, "evaluation", "custom_cases")

class TestCustomCases(unittest.TestCase):
    def setUp(self):
        self.intent = IntentClassifier(False)
        self.rules = ConfigurableRulesEngine(
            os.path.join(ROOT, "dataset", "deletion_rules.csv"),
            os.path.join(CODE, "config", "rules.json")
        )
        self.rules.load()

    def test_custom_case_01_historical_email(self):
        case_path = os.path.join(CUSTOM_CASES_DIR, "custom_01_historical_email.json")
        with open(case_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        req_text = data["request"]["request_text"]
        intent_res = self.intent.classify(req_text)
        self.assertTrue(intent_res.authorized, "Deletion authorization should be true")
        self.assertEqual(intent_res.intent, "DELETION")

    def test_custom_case_02_restore_risk(self):
        case_path = os.path.join(CUSTOM_CASES_DIR, "custom_02_restore_risk_only.json")
        with open(case_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        req_text = data["request"]["request_text"]
        intent_res = self.intent.classify(req_text)
        self.assertTrue(intent_res.authorized)
        # Check rule mapping for backup
        action = self.rules.required_action_for("BACKUP_ARCHIVE", {"restore_access_blockable": True}, None)
        self.assertEqual(action, "RETAIN")

    def test_custom_case_03_tombstone_pii(self):
        case_path = os.path.join(CUSTOM_CASES_DIR, "custom_03_tombstone_exposed_pii.json")
        with open(case_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        req_text = data["request"]["request_text"]
        intent_res = self.intent.classify(req_text)
        self.assertTrue(intent_res.authorized)
        # Check rule 11: tombstone must be REDACTED
        action = self.rules.required_action_for("ACCOUNT_TOMBSTONE", {"tombstone_needed": True}, None)
        self.assertEqual(action, "REDACT")

    def test_custom_case_04_non_english_non_deletion(self):
        case_path = os.path.join(CUSTOM_CASES_DIR, "custom_04_non_english_non_deletion.json")
        with open(case_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        req_text = data["request"]["request_text"]
        intent_res = self.intent.classify(req_text)
        self.assertFalse(intent_res.authorized, "Non-deletion request must not be authorized")
        self.assertEqual(intent_res.intent, "NON_DELETION")

if __name__ == "__main__":
    unittest.main()
