"""Scanner adapters with consistent status and failure semantics."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol


class ScanStatus(StrEnum):
    SUCCESS = "success"
    NO_FINDINGS = "no_findings"
    INVALID_OUTPUT = "invalid_output"
    TIMEOUT = "timeout"
    NOT_AVAILABLE = "not_available"
    EXECUTION_ERROR = "execution_error"


@dataclass(slots=True)
class ScanResult:
    scanner: str
    status: ScanStatus
    sarif: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class Scanner(Protocol):
    name: str

    def run(self) -> ScanResult: ...


@dataclass(slots=True)
class SarifFileScanner:
    path: str | Path
    max_output_bytes: int = 25_000_000
    name: str = "SARIF file"

    def run(self) -> ScanResult:
        path = Path(self.path)
        try:
            size = path.stat().st_size
            if not path.is_file():
                raise OSError("path is not a regular file")
            if size > self.max_output_bytes:
                return ScanResult(
                    self.name,
                    ScanStatus.INVALID_OUTPUT,
                    errors=[f"SARIF file exceeds {self.max_output_bytes} byte limit"],
                )
            document = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return ScanResult(
                self.name,
                ScanStatus.NOT_AVAILABLE,
                errors=[f"SARIF file not found: {path}"],
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return ScanResult(
                self.name,
                ScanStatus.INVALID_OUTPUT,
                errors=[f"Unable to read SARIF: {exc}"],
            )
        if not isinstance(document, dict):
            return ScanResult(
                self.name,
                ScanStatus.INVALID_OUTPUT,
                errors=["SARIF root must be an object"],
            )
        return ScanResult(
            self.name,
            ScanStatus.SUCCESS,
            sarif=document,
            metadata={"path": str(path), "bytes": size},
        )


@dataclass(slots=True)
class SemgrepScanner:
    target: str | Path
    rule_config: str | Path
    timeout_seconds: float = 60.0
    workspace: str | Path = "."
    executable: str = "semgrep"
    name: str = "Semgrep"

    def run(self) -> ScanResult:
        executable = shutil.which(self.executable)
        if not executable:
            return ScanResult(
                self.name,
                ScanStatus.NOT_AVAILABLE,
                errors=["Semgrep executable was not found"],
            )
        try:
            target = self._contained_path(self.target)
            rules = self._contained_path(self.rule_config)
        except ValueError as exc:
            return ScanResult(self.name, ScanStatus.EXECUTION_ERROR, errors=[str(exc)])
        if not target.exists() or not rules.is_file():
            return ScanResult(
                self.name,
                ScanStatus.NOT_AVAILABLE,
                errors=["Scan target or rule configuration is missing"],
            )

        with tempfile.TemporaryDirectory(prefix="agentic-vapt-") as temporary_directory:
            output_path = Path(temporary_directory) / "results.sarif"
            command = [
                executable,
                "--config",
                str(rules),
                str(target),
                "--sarif",
                "--output",
                str(output_path),
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout_seconds,
                    check=False,
                    shell=False,
                )
            except subprocess.TimeoutExpired:
                return ScanResult(self.name, ScanStatus.TIMEOUT, errors=["Semgrep timed out"])
            except OSError as exc:
                return ScanResult(
                    self.name,
                    ScanStatus.EXECUTION_ERROR,
                    errors=[f"Semgrep failed: {exc}"],
                )
            metadata = {
                "return_code": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            }
            if completed.returncode not in (0, 1):
                return ScanResult(
                    self.name,
                    ScanStatus.EXECUTION_ERROR,
                    errors=[f"Semgrep exited with code {completed.returncode}"],
                    metadata=metadata,
                )
            try:
                document = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                return ScanResult(
                    self.name,
                    ScanStatus.INVALID_OUTPUT,
                    errors=[f"Semgrep produced invalid SARIF: {exc}"],
                    metadata=metadata,
                )
            if not isinstance(document, dict):
                return ScanResult(
                    self.name,
                    ScanStatus.INVALID_OUTPUT,
                    errors=["Semgrep SARIF root is not an object"],
                )
            return ScanResult(self.name, ScanStatus.SUCCESS, sarif=document, metadata=metadata)

    def _contained_path(self, value: str | Path) -> Path:
        root = Path(self.workspace).resolve()
        candidate = (root / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError(f"Path escapes configured workspace: {value}")
        return candidate


@dataclass(slots=True)
class InMemoryScanner:
    document: object
    name: str = "Mock scanner"

    def run(self) -> ScanResult:
        if not isinstance(self.document, dict):
            return ScanResult(
                self.name,
                ScanStatus.INVALID_OUTPUT,
                errors=["Mock SARIF root is not an object"],
            )
        return ScanResult(self.name, ScanStatus.SUCCESS, sarif=self.document)
