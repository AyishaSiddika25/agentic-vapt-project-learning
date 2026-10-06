from __future__ import annotations

import tempfile
import unittest

from agentic_vapt.config import AppConfig
from agentic_vapt.models import GateDecision
from agentic_vapt.pipeline import AssessmentPipeline
from agentic_vapt.reporting import write_reports
from agentic_vapt.scanners import InMemoryScanner
from tests.helpers import make_sarif


class FailingScanner:
    name = "Broken scanner"

    def run(self) -> object:
        raise RuntimeError("simulated failure")


class EndToEndPipelineTests(unittest.TestCase):
    def test_complete_mocked_assessment(self) -> None:
        semgrep = InMemoryScanner(make_sarif(tool="Semgrep"), name="Semgrep adapter")
        codeql = InMemoryScanner(
            make_sarif(tool="CodeQL", rule_id="py/sql-query-built-from-user-controlled-sources"),
            name="CodeQL adapter",
        )
        result = AssessmentPipeline([semgrep, codeql], AppConfig()).run()
        self.assertEqual(result.stage_counts["normalized"], 2)
        self.assertEqual(result.stage_counts["deduplicated"], 1)
        self.assertEqual(result.gate.decision, GateDecision.BLOCK)
        self.assertEqual(result.findings[0].sources, ["CodeQL", "Semgrep"])
        self.assertEqual(len(result.analyses), 1)

    def test_empty_successful_scan_passes(self) -> None:
        scanner = InMemoryScanner({"version": "2.1.0", "runs": []})
        result = AssessmentPipeline([scanner], AppConfig()).run()
        self.assertEqual(result.gate.decision, GateDecision.PASS)
        self.assertEqual(result.findings, [])

    def test_scanner_failure_fails_closed_as_unknown(self) -> None:
        result = AssessmentPipeline([FailingScanner()], AppConfig()).run()  # type: ignore[list-item]
        self.assertEqual(result.gate.decision, GateDecision.UNKNOWN)
        self.assertTrue(result.errors)

    def test_partial_scanner_failure_prevents_false_pass(self) -> None:
        empty = InMemoryScanner({"version": "2.1.0", "runs": []})
        result = AssessmentPipeline([empty, FailingScanner()], AppConfig()).run()  # type: ignore[list-item]
        self.assertEqual(result.gate.decision, GateDecision.UNKNOWN)

    def test_suppressed_finding_is_not_sent_to_ai(self) -> None:
        config = AppConfig(
            suppressions=(
                {
                    "id": "demo",
                    "reason": "accepted for fixture",
                    "selectors": {"rule_id": "python.sql-injection"},
                },
            )
        )
        result = AssessmentPipeline([InMemoryScanner(make_sarif())], config).run()
        self.assertEqual(result.findings[0].decision, GateDecision.SUPPRESSED)
        self.assertEqual(result.analyses, [])

    def test_reports_include_suppressed_and_blocked_states(self) -> None:
        result = AssessmentPipeline([InMemoryScanner(make_sarif())], AppConfig()).run()
        with tempfile.TemporaryDirectory() as directory:
            json_path, markdown_path = write_reports(result, directory)
            json_report = json_path.read_text(encoding="utf-8")
            markdown_report = markdown_path.read_text(encoding="utf-8")
        self.assertIn('"decision": "block"', json_report)
        self.assertIn("Overall security gate: **BLOCK**", markdown_report)
        self.assertIn("Fingerprint", markdown_report)


if __name__ == "__main__":
    unittest.main()
