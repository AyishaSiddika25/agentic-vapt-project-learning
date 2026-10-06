from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentic_vapt.models import Severity
from agentic_vapt.sarif import normalize_sarif
from agentic_vapt.scanners import SarifFileScanner, ScanStatus
from tests.helpers import make_sarif


class SarifNormalizationTests(unittest.TestCase):
    def test_valid_sarif_preserves_metadata_and_evidence(self) -> None:
        outcome = normalize_sarif(make_sarif())
        self.assertEqual(outcome.errors, [])
        self.assertEqual(len(outcome.findings), 1)
        finding = outcome.findings[0]
        self.assertEqual(finding.scanner, "Semgrep")
        self.assertEqual(finding.rule_id, "python.sql-injection")
        self.assertEqual(finding.vulnerability_type, "CWE-89")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.primary_location.start_column, 5)
        self.assertIn("query = 'SELECT' + user_input", finding.evidence)
        self.assertEqual(
            finding.raw_metadata["sarif_fingerprints"]["scanner/v1"],
            "scanner-owned-fingerprint",
        )

    def test_empty_sarif_is_valid(self) -> None:
        outcome = normalize_sarif({"version": "2.1.0", "runs": []})
        self.assertEqual(outcome.findings, [])
        self.assertEqual(outcome.errors, [])

    def test_missing_optional_fields_are_safe(self) -> None:
        document = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Tool"}}, "results": [{}]}],
        }
        outcome = normalize_sarif(document)
        self.assertEqual(len(outcome.findings), 1)
        self.assertEqual(outcome.findings[0].resource, "")
        self.assertEqual(outcome.findings[0].severity, Severity.UNKNOWN)

    def test_malformed_sarif_returns_errors(self) -> None:
        outcome = normalize_sarif({"version": "1.0", "runs": []})
        self.assertEqual(outcome.findings, [])
        self.assertTrue(outcome.errors)
        self.assertTrue(normalize_sarif("not-an-object").errors)

    def test_malformed_result_does_not_drop_other_results(self) -> None:
        document = make_sarif()
        document["runs"][0]["results"].insert(0, "bad")
        outcome = normalize_sarif(document)
        self.assertEqual(len(outcome.findings), 1)
        self.assertTrue(outcome.errors)

    def test_sarif_file_scanner_handles_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.sarif"
            path.write_text("{", encoding="utf-8")
            result = SarifFileScanner(path).run()
        self.assertEqual(result.status, ScanStatus.INVALID_OUTPUT)
        self.assertTrue(result.errors)

    def test_sarif_file_scanner_reads_valid_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "valid.sarif"
            path.write_text(json.dumps(make_sarif()), encoding="utf-8")
            result = SarifFileScanner(path).run()
        self.assertEqual(result.status, ScanStatus.SUCCESS)
        self.assertIsNotNone(result.sarif)


if __name__ == "__main__":
    unittest.main()
