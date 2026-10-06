"""Auditable JSON and Markdown report generation."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path

from .pipeline import AssessmentResult


def write_reports(result: AssessmentResult, output_directory: str | Path) -> tuple[Path, Path]:
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "assessment.json"
    markdown_path = output / "assessment.md"
    _atomic_write(json_path, json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n")
    _atomic_write(markdown_path, render_markdown(result))
    return json_path, markdown_path


def render_markdown(result: AssessmentResult) -> str:
    lines = [
        "# Agentic VAPT Assessment",
        "",
        f"Overall security gate: **{result.gate.decision.value.upper()}**",
        "",
        "## Summary",
        "",
    ]
    lines.extend(f"- {reason}" for reason in result.gate.reasons)
    lines.extend(["", "## Pipeline", ""])
    lines.extend(
        f"- {name.replace('_', ' ').title()}: {count}" for name, count in result.stage_counts.items()
    )
    lines.extend(["", "## Scanner status", ""])
    for scan in result.scanner_results:
        lines.append(f"- {scan.scanner}: **{scan.status.value.upper()}**")
        lines.extend(f"  - Error: {error}" for error in scan.errors)
    if result.errors:
        lines.extend(["", "## Errors and warnings", ""])
        lines.extend(f"- {error}" for error in result.errors)
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings were detected.")
    analysis_by_fingerprint = {analysis.fingerprint: analysis for analysis in result.analyses}
    for index, finding in enumerate(result.findings, start=1):
        location = finding.primary_location
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- Decision: **{finding.decision.value.upper()}**",
                f"- Severity: {finding.severity.value}",
                f"- Confidence: {finding.confidence if finding.confidence is not None else 'unknown'}",
                f"- Source(s): {', '.join(finding.sources or [finding.scanner])}",
                f"- Rule: {finding.rule_id or 'not supplied'}",
                f"- Vulnerability type: {finding.vulnerability_type or 'not supplied'}",
                f"- Resource: {finding.resource or 'not supplied'}",
                f"- Location: {location.start_line or '?'}:{location.start_column or '?'}",
                f"- Endpoint: {finding.endpoint or 'not supplied'}",
                f"- Fingerprint: `{finding.fingerprint}`",
                f"- Validity: {finding.validity.value}",
                f"- Suppression: {finding.suppression_status.value}",
                f"- Reachability: {finding.reachability.value} — {finding.reachability_reason}",
                f"- Risk score: {finding.risk_score}",
                "- Decision reason: " + " ".join(finding.decision_reasons),
            ]
        )
        if finding.suppression_reason:
            lines.append(f"- Suppression reason: {finding.suppression_reason}")
        if finding.evidence:
            lines.append("- Evidence:")
            lines.extend(f"  - {item}" for item in finding.evidence)
        analysis = analysis_by_fingerprint.get(finding.fingerprint)
        if analysis:
            lines.extend(
                [
                    f"- Agentic analysis status: {analysis.status}",
                    f"- Agentic reasoning: {analysis.security_reasoning or analysis.error}",
                    f"- Recommended next step: {analysis.recommended_next_step or 'unavailable'}",
                ]
            )
        elif finding.remediation:
            lines.append(f"- Recommended remediation: {finding.remediation}")
        lines.append("")
    lines.extend(
        [
            "## Control boundary",
            "",
            (
                "Agentic analysis ran only after validation, deduplication, suppression, reachability, "
                "and the deterministic security gate. AI output is decision support and cannot modify "
                "gate decisions."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _atomic_write(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary_name, path)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
