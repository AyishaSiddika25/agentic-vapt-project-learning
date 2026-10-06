"""Command-line entry point for local and CI assessments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import AppConfig
from .models import GateDecision
from .pipeline import AssessmentPipeline
from .reporting import write_reports
from .scanners import SarifFileScanner, SemgrepScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Agentic VAPT finding pipeline")
    parser.add_argument("--sarif", action="append", default=[], help="Existing SARIF file (repeatable)")
    parser.add_argument("--target", help="Local target path to scan with Semgrep")
    parser.add_argument("--rules", help="Local Semgrep rule configuration")
    parser.add_argument("--config", help="Agentic VAPT JSON configuration")
    parser.add_argument("--output-dir", default="reports/latest", help="Report output directory")
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit zero after producing a report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if bool(arguments.target) != bool(arguments.rules):
        print("--target and --rules must be supplied together", file=sys.stderr)
        return 64
    if not arguments.sarif and not arguments.target:
        print(
            "Provide at least one --sarif file or a --target with --rules",
            file=sys.stderr,
        )
        return 64
    try:
        config = AppConfig.load(arguments.config)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 64
    scanners = [SarifFileScanner(path, config.scanner.max_output_bytes) for path in arguments.sarif]
    if arguments.target:
        scanners.append(
            SemgrepScanner(
                target=arguments.target,
                rule_config=arguments.rules,
                timeout_seconds=config.scanner.timeout_seconds,
                workspace=Path.cwd(),
            )
        )
    result = AssessmentPipeline(scanners=scanners, config=config).run()
    try:
        json_path, markdown_path = write_reports(result, arguments.output_dir)
    except OSError as exc:
        print(f"Unable to write reports: {exc}", file=sys.stderr)
        return 74
    print(f"Security gate: {result.gate.decision.value.upper()}")
    print(f"Findings: {len(result.findings)}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    if arguments.exit_zero:
        return 0
    if result.gate.decision is GateDecision.BLOCK:
        return 2
    if result.gate.decision is GateDecision.UNKNOWN:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
