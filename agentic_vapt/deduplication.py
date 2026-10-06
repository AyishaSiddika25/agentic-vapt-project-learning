"""Deterministic finding correlation and metadata-preserving merge logic."""

from __future__ import annotations

from .fingerprint import assign_identity
from .models import Finding, Location, Severity

_SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    correlated: dict[str, Finding] = {}
    for finding in findings:
        assign_identity(finding)
        existing = correlated.get(finding.fingerprint)
        if existing is None:
            correlated[finding.fingerprint] = finding
        else:
            _merge(existing, finding)
    return [correlated[key] for key in sorted(correlated)]


def _merge(target: Finding, duplicate: Finding) -> None:
    if _SEVERITY_RANK[duplicate.severity] > _SEVERITY_RANK[target.severity]:
        target.severity = duplicate.severity
    if duplicate.confidence is not None and (
        target.confidence is None or duplicate.confidence > target.confidence
    ):
        target.confidence = duplicate.confidence
    target.sources = sorted(set(target.sources + duplicate.sources + [target.scanner, duplicate.scanner]))
    target.evidence = sorted(set(target.evidence + duplicate.evidence))
    target.locations = _merge_locations(target.locations, duplicate.locations)
    for field_name in (
        "description",
        "vulnerability_type",
        "resource",
        "endpoint",
        "remediation",
    ):
        if not getattr(target, field_name) and getattr(duplicate, field_name):
            setattr(target, field_name, getattr(duplicate, field_name))
    duplicates = target.raw_metadata.setdefault("correlated_findings", [])
    duplicates.append(
        {
            "scanner": duplicate.scanner,
            "rule_id": duplicate.rule_id,
            "title": duplicate.title,
            "severity": duplicate.severity.value,
            "raw_metadata": duplicate.raw_metadata,
        }
    )


def _merge_locations(first: list[Location], second: list[Location]) -> list[Location]:
    unique: dict[tuple[object, ...], Location] = {}
    for location in first + second:
        key = (
            location.resource,
            location.uri,
            location.start_line,
            location.start_column,
            location.end_line,
            location.end_column,
        )
        unique[key] = location
    return [unique[key] for key in sorted(unique, key=lambda item: tuple(str(part) for part in item))]
