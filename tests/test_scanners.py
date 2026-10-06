from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentic_vapt.scanners import ScanStatus, SemgrepScanner


class SemgrepScannerTests(unittest.TestCase):
    def test_missing_executable_is_observable(self) -> None:
        with patch("agentic_vapt.scanners.shutil.which", return_value=None):
            result = SemgrepScanner("src", "rules.yml").run()
        self.assertEqual(result.status, ScanStatus.NOT_AVAILABLE)
        self.assertTrue(result.errors)

    def test_path_escape_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            root.mkdir()
            rules = root / "rules.yml"
            rules.write_text("rules: []", encoding="utf-8")
            with patch("agentic_vapt.scanners.shutil.which", return_value="semgrep"):
                result = SemgrepScanner(root.parent, rules, workspace=root).run()
        self.assertEqual(result.status, ScanStatus.EXECUTION_ERROR)
        self.assertIn("escapes", result.errors[0])

    def test_timeout_is_observable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sample.py"
            rules = root / "rules.yml"
            target.write_text("value = 1", encoding="utf-8")
            rules.write_text("rules: []", encoding="utf-8")
            with (
                patch("agentic_vapt.scanners.shutil.which", return_value="semgrep"),
                patch(
                    "agentic_vapt.scanners.subprocess.run",
                    side_effect=subprocess.TimeoutExpired("semgrep", 1),
                ),
            ):
                result = SemgrepScanner(target, rules, timeout_seconds=1, workspace=root).run()
        self.assertEqual(result.status, ScanStatus.TIMEOUT)

    def test_invalid_scanner_output_is_observable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sample.py"
            rules = root / "rules.yml"
            target.write_text("value = 1", encoding="utf-8")
            rules.write_text("rules: []", encoding="utf-8")
            completed = subprocess.CompletedProcess(["semgrep"], 0, stdout="", stderr="")
            with (
                patch("agentic_vapt.scanners.shutil.which", return_value="semgrep"),
                patch("agentic_vapt.scanners.subprocess.run", return_value=completed),
            ):
                result = SemgrepScanner(target, rules, workspace=root).run()
        self.assertEqual(result.status, ScanStatus.INVALID_OUTPUT)


if __name__ == "__main__":
    unittest.main()
