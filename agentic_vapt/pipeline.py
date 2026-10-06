"""End-to-end orchestration of scanners, deterministic controls, and analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .ai import AnalysisResult, Analyzer, create_analyzer
from .config import AppConfig
from .deduplication import deduplicate_findings
from .gate import GateResult, security_gate
from .models import Finding, GateDecision
from .reachability import evaluate_reachability
from .sarif import normalize_sarif
from .scanners import Scanner, ScanResult, ScanStatus
from .suppression import apply_suppressions
from .validation import validate_finding


@dataclass(slots=True)
class AssessmentResult:
    findings: list[Finding]
    gate: GateResult
    scanner_results: list[ScanResult]
    analyses: list[AnalysisResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stage_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate.to_dict(),
            "stage_counts": self.stage_counts,
            "errors": self.errors,
            "scanners": [
                {
                    "scanner": scan.scanner,
                    "status": scan.status.value,
                    "errors": scan.errors,
                    "metadata": scan.metadata,
                }
                for scan in self.scanner_results
            ],
            "findings": [finding.to_dict() for finding in self.findings],
            "analyses": [analysis.to_dict() for analysis in self.analyses],
        }


@dataclass(slots=True)
class AssessmentPipeline:
    scanners: list[Scanner]
    config: AppConfig = field(default_factory=AppConfig)
    analyzer: Analyzer | None = None

    def run(self) -> AssessmentResult:
        scanner_results: list[ScanResult] = []
        normalized: list[Finding] = []
        errors: list[str] = []
        successful_inputs = 0

        for scanner in self.scanners:
            try:
                scan = scanner.run()
            except Exception as exc:  # noqa: BLE001 - adapters are an external trust boundary.
                scan = ScanResult(
                    scanner=getattr(scanner, "name", type(scanner).__name__),
                    status=ScanStatus.EXECUTION_ERROR,
                    errors=[f"Unexpected scanner failure: {type(exc).__name__}: {exc}"],
                )
            scanner_results.append(scan)
            errors.extend(f"{scan.scanner}: {message}" for message in scan.errors)
            if scan.status is not ScanStatus.SUCCESS or scan.sarif is None:
                continue
            outcome = normalize_sarif(scan.sarif)
            if outcome.errors:
                errors.extend(f"{scan.scanner}: {message}" for message in outcome.errors)
            if not outcome.findings and outcome.errors:
                scan.status = ScanStatus.INVALID_OUTPUT
                continue
            successful_inputs += 1
            normalized.extend(outcome.findings)
            if not outcome.findings:
                scan.status = ScanStatus.NO_FINDINGS

        for finding in normalized:
            validate_finding(finding)
        unique = deduplicate_findings(normalized)
        suppression_outcome = apply_suppressions(unique, self.config.suppressions)
        errors.extend(suppression_outcome.errors)
        for finding in suppression_outcome.findings:
            evaluate_reachability(finding)
        gate = security_gate(suppression_outcome.findings, self.config.gate)
        if successful_inputs == 0:
            gate.decision = GateDecision.UNKNOWN
            gate.reasons.insert(0, "No scanner produced valid SARIF; the assessment cannot pass.")
        elif gate.decision is GateDecision.PASS and any(
            scan.status not in {ScanStatus.SUCCESS, ScanStatus.NO_FINDINGS} for scan in scanner_results
        ):
            gate.decision = GateDecision.UNKNOWN
            gate.reasons.insert(0, "At least one scanner failed, so a passing assessment is not conclusive.")

        analyzer = self.analyzer
        if analyzer is None:
            try:
                analyzer = create_analyzer(self.config.ai)
            except ValueError as exc:
                errors.append(str(exc))
        analyses: list[AnalysisResult] = []
        allowed = set(self.config.gate.analyze_decisions)
        if analyzer:
            for finding in gate.findings:
                if finding.decision.value not in allowed:
                    continue
                try:
                    analyses.append(analyzer.analyze(finding))
                except Exception as exc:  # noqa: BLE001 - providers cannot abort the gate.
                    analyses.append(
                        AnalysisResult(
                            fingerprint=finding.fingerprint,
                            status="error",
                            error=f"Unexpected analyzer failure: {type(exc).__name__}: {exc}",
                            provider=type(analyzer).__name__,
                        )
                    )

        return AssessmentResult(
            findings=gate.findings,
            gate=gate,
            scanner_results=scanner_results,
            analyses=analyses,
            errors=errors,
            stage_counts={
                "scanner_results": len(scanner_results),
                "normalized": len(normalized),
                "deduplicated": len(unique),
                "suppressed": sum(f.suppression_status.value == "suppressed" for f in unique),
                "analyzed": len(analyses),
            },
        )
