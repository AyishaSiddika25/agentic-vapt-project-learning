import unittest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock


# Add the Day-06 directory to Python's import path
sys.path.insert(
    0,
    str(Path(__file__).resolve().parent)
)

from semgrep_adapter import (
    load_sarif,
    normalize_findings,
    generate_fingerprint,
    determine_scan_status,
    run_semgrep,
)


class TestSemgrepAdapter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sarif_file = Path(
            "Day-06/semgrep_results.sarif"
        )

        cls.sarif_data = load_sarif(
            str(cls.sarif_file)
        )

    # --------------------------------------------------
    # SARIF TESTS
    # --------------------------------------------------

    def test_sarif_file_exists(self):
        """Verify that the SARIF fixture exists."""

        self.assertTrue(
            self.sarif_file.exists(),
            "SARIF fixture file does not exist."
        )

    def test_sarif_version(self):
        """Verify SARIF version is 2.1.0."""

        self.assertEqual(
            self.sarif_data.get("version"),
            "2.1.0"
        )

    # --------------------------------------------------
    # NORMALIZATION TESTS
    # --------------------------------------------------

    def test_finding_count(self):
        """Verify the expected number of findings."""

        findings = normalize_findings(
            self.sarif_data
        )

        self.assertEqual(
            len(findings),
            1
        )

    def test_finding_fields(self):
        """Verify required normalized finding fields."""

        findings = normalize_findings(
            self.sarif_data
        )

        finding = findings[0]

        self.assertEqual(
            finding["scanner"],
            "Semgrep"
        )

        self.assertEqual(
            finding["rule_id"],
            "Day-06.semgrep_rules.simple-sql-string-concatenation"
        )

        self.assertEqual(
            finding["severity"],
            "warning"
        )

        self.assertEqual(
            finding["file"],
            "Day-06\\semgrep_demo.py"
        )

        self.assertEqual(
            finding["start_line"],
            2
        )

        self.assertEqual(
            finding["end_line"],
            2
        )

    # --------------------------------------------------
    # FINGERPRINT TESTS
    # --------------------------------------------------

    def test_fingerprint_is_deterministic(self):
        """Verify the same finding produces the same fingerprint."""

        fingerprint_1 = generate_fingerprint(
            "test-rule",
            "Day-06\\semgrep_demo.py",
            2,
            2,
        )

        fingerprint_2 = generate_fingerprint(
            "test-rule",
            "Day-06\\semgrep_demo.py",
            2,
            2,
        )

        self.assertEqual(
            fingerprint_1,
            fingerprint_2
        )

    def test_fingerprint_length(self):
        """Verify fingerprint is a SHA-256 hexadecimal hash."""

        fingerprint = generate_fingerprint(
            "test-rule",
            "Day-06\\semgrep_demo.py",
            2,
            2,
        )

        self.assertEqual(
            len(fingerprint),
            64
        )

        self.assertTrue(
            all(
                character in "0123456789abcdef"
                for character in fingerprint
            )
        )

    def test_different_findings_have_different_fingerprints(self):
        """Verify different finding locations produce different fingerprints."""

        fingerprint_1 = generate_fingerprint(
            "test-rule",
            "Day-06\\semgrep_demo.py",
            2,
            2,
        )

        fingerprint_2 = generate_fingerprint(
            "test-rule",
            "Day-06\\semgrep_demo.py",
            10,
            10,
        )

        self.assertNotEqual(
            fingerprint_1,
            fingerprint_2
        )

    # --------------------------------------------------
    # SCAN STATUS TESTS
    # --------------------------------------------------

    def test_scan_status_findings(self):
        """Verify a SARIF file containing findings returns FINDINGS."""

        findings = normalize_findings(
            self.sarif_data
        )

        status = determine_scan_status(
            self.sarif_data,
            findings,
            "SUCCESS",
        )

        self.assertEqual(
            status,
            "FINDINGS"
        )

    def test_scan_status_no_findings(self):
        """Verify valid SARIF with no findings returns NO_FINDINGS."""

        sarif_without_findings = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": []
                }
            ]
        }

        findings = normalize_findings(
            sarif_without_findings
        )

        status = determine_scan_status(
            sarif_without_findings,
            findings,
            "SUCCESS",
        )

        self.assertEqual(
            status,
            "NO_FINDINGS"
        )

    def test_scan_status_invalid_output(self):
        """Verify malformed SARIF returns INVALID_OUTPUT."""

        invalid_sarif = {
            "version": "1.0"
        }

        findings = []

        status = determine_scan_status(
            invalid_sarif,
            findings,
            "SUCCESS",
        )

        self.assertEqual(
            status,
            "INVALID_OUTPUT"
        )

    # --------------------------------------------------
    # FAILURE SEMANTICS TESTS
    # --------------------------------------------------

    def test_scan_status_timeout(self):
        """Verify timeout returns TIMEOUT."""

        status = determine_scan_status(
            {},
            [],
            "TIMEOUT",
        )

        self.assertEqual(
            status,
            "TIMEOUT"
        )

    def test_scan_status_execution_error(self):
        """Verify scanner execution failure returns EXECUTION_ERROR."""

        status = determine_scan_status(
            {},
            [],
            "EXECUTION_ERROR",
        )

        self.assertEqual(
            status,
            "EXECUTION_ERROR"
        )

    # --------------------------------------------------
    # SEMGREP RUNNER TESTS
    # --------------------------------------------------

    @patch("semgrep_adapter.subprocess.run")
    def test_semgrep_runner_success(self, mock_run):
        """Verify Semgrep runner reports SUCCESS."""

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        mock_run.return_value = mock_result

        status = run_semgrep(
            "Day-06/semgrep_rules/sql-injection.yml",
            "Day-06/semgrep_demo.py",
            "Day-06/test_results.sarif",
        )

        self.assertEqual(
            status,
            "SUCCESS"
        )

        mock_run.assert_called_once()

    @patch("semgrep_adapter.subprocess.run")
    def test_semgrep_runner_finding_exit_code(self, mock_run):
        """Verify Semgrep exit code 1 is treated as successful execution."""

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = ""

        mock_run.return_value = mock_result

        status = run_semgrep(
            "Day-06/semgrep_rules/sql-injection.yml",
            "Day-06/semgrep_demo.py",
            "Day-06/test_results.sarif",
        )

        self.assertEqual(
            status,
            "SUCCESS"
        )

    @patch("semgrep_adapter.subprocess.run")
    def test_semgrep_runner_execution_error(self, mock_run):
        """Verify unexpected Semgrep exit code returns EXECUTION_ERROR."""

        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = ""
        mock_result.stderr = ""

        mock_run.return_value = mock_result

        status = run_semgrep(
            "Day-06/semgrep_rules/sql-injection.yml",
            "Day-06/semgrep_demo.py",
            "Day-06/test_results.sarif",
        )

        self.assertEqual(
            status,
            "EXECUTION_ERROR"
        )

    @patch("semgrep_adapter.subprocess.run")
    def test_semgrep_runner_timeout(self, mock_run):
        """Verify Semgrep timeout returns TIMEOUT."""

        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="semgrep",
            timeout=60,
        )

        status = run_semgrep(
            "Day-06/semgrep_rules/sql-injection.yml",
            "Day-06/semgrep_demo.py",
            "Day-06/test_results.sarif",
        )

        self.assertEqual(
            status,
            "TIMEOUT"
        )

    @patch("semgrep_adapter.subprocess.run")
    def test_semgrep_runner_not_found(self, mock_run):
        """Verify missing Semgrep executable returns EXECUTION_ERROR."""

        mock_run.side_effect = FileNotFoundError()

        status = run_semgrep(
            "Day-06/semgrep_rules/sql-injection.yml",
            "Day-06/semgrep_demo.py",
            "Day-06/test_results.sarif",
        )

        self.assertEqual(
            status,
            "EXECUTION_ERROR"
        )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )