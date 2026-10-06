"""Central deterministic risk evaluation and security gate."""

from __future__ import annotations

from dataclasses import dataclass

from .config import GatePolicy
from .models import (
    Finding,
    GateDecision,
    Reachability,
    Severity,
    SuppressionStatus,
    Validity,
)

_BASE_RISK = {
    Severity.UNKNOWN: 0.0,
    Severity.INFO: 1.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 5.5,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.5,
}


@dataclass(slots=True)
class GateResult:
    decision: GateDecision
    findings: list[Finding]
    reasons: list[str]
    counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision.value,
            "reasons": self.reasons,
            "counts": self.counts,
        }


def evaluate_finding(finding: Finding, policy: GatePolicy) -> Finding:
    finding.risk_score = _risk_score(finding)
    if finding.suppression_status is SuppressionStatus.SUPPRESSED:
        finding.decision = GateDecision.SUPPRESSED
        finding.decision_reasons = [
            f"Matched suppression {finding.suppression_rule_id}: {finding.suppression_reason}"
        ]
        return finding
    if finding.validity is Validity.INVALID:
        finding.decision = GateDecision.UNKNOWN
        finding.decision_reasons = ["Finding is invalid: " + "; ".join(finding.validation_errors)]
        return finding
    if finding.severity is Severity.UNKNOWN:
        finding.decision = GateDecision.UNKNOWN
        finding.decision_reasons = [
            "Severity is unknown, so policy cannot make a deterministic risk decision."
        ]
        return finding
    if finding.reachability is Reachability.UNREACHABLE:
        finding.decision = GateDecision.PASS
        finding.decision_reasons = [
            "Finding has explicit unreachable evidence; detection remains in the report for auditability."
        ]
        return finding

    severity = finding.severity.value
    if severity in policy.block_severities:
        if finding.reachability is Reachability.REACHABLE:
            finding.decision = GateDecision.BLOCK
            finding.decision_reasons = [
                f"{severity.title()} severity is reachable and meets the configured block policy."
            ]
        elif policy.block_unknown_reachability:
            finding.decision = GateDecision.BLOCK
            finding.decision_reasons = [
                f"{severity.title()} severity with unknown reachability is configured to block."
            ]
        else:
            finding.decision = GateDecision.WARN
            finding.decision_reasons = [
                f"{severity.title()} severity requires attention, but reachability is unknown."
            ]
        return finding
    if severity in policy.warn_severities:
        finding.decision = GateDecision.WARN
        finding.decision_reasons = [f"{severity.title()} severity meets the configured warning policy."]
        return finding
    finding.decision = GateDecision.PASS
    finding.decision_reasons = [f"{severity.title()} severity is below configured gate thresholds."]
    return finding


def security_gate(findings: list[Finding], policy: GatePolicy) -> GateResult:
    for finding in findings:
        evaluate_finding(finding, policy)
    counts = {decision.value: 0 for decision in GateDecision}
    for finding in findings:
        counts[finding.decision.value] += 1
    if counts[GateDecision.BLOCK.value]:
        overall = GateDecision.BLOCK
    elif counts[GateDecision.WARN.value]:
        overall = GateDecision.WARN
    elif counts[GateDecision.UNKNOWN.value]:
        overall = GateDecision.UNKNOWN
    else:
        overall = GateDecision.PASS
    reasons = [
        f"{counts[decision.value]} finding(s) received {decision.value.upper()}"
        for decision in GateDecision
        if counts[decision.value]
    ]
    if not findings:
        reasons = ["No findings were detected."]
    return GateResult(decision=overall, findings=findings, reasons=reasons, counts=counts)


def _risk_score(finding: Finding) -> float:
    score = _BASE_RISK[finding.severity]
    if finding.reachability is Reachability.REACHABLE:
        score += 1.0
    elif finding.reachability is Reachability.UNREACHABLE:
        score -= 2.0
    if finding.confidence is not None:
        score += (finding.confidence - 0.5) * 1.5
    return round(max(0.0, min(10.0, score)), 2)
