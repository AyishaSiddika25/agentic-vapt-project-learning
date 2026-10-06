"""Configurable, traceable finding suppression."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any

from .fingerprint import normalize_endpoint, normalize_resource
from .models import Finding, SuppressionStatus

_SELECTORS = {
    "fingerprint",
    "rule_id",
    "vulnerability_type",
    "resource",
    "endpoint",
    "scanner",
}


@dataclass(frozen=True, slots=True)
class SuppressionRule:
    rule_id: str
    reason: str
    selectors: dict[str, str]
    expires_at: datetime | None = None


@dataclass(slots=True)
class SuppressionOutcome:
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)


def apply_suppressions(findings: list[Finding], raw_rules: tuple[dict[str, Any], ...]) -> SuppressionOutcome:
    rules: list[SuppressionRule] = []
    errors: list[str] = []
    for index, raw_rule in enumerate(raw_rules):
        try:
            rules.append(_parse_rule(raw_rule, index))
        except ValueError as exc:
            errors.append(str(exc))

    now = datetime.now(UTC)
    for finding in findings:
        finding.suppression_status = SuppressionStatus.ACTIVE
        for rule in rules:
            if rule.expires_at and rule.expires_at <= now:
                continue
            if _matches(finding, rule.selectors):
                finding.suppression_status = SuppressionStatus.SUPPRESSED
                finding.suppression_reason = rule.reason
                finding.suppression_rule_id = rule.rule_id
                break
    return SuppressionOutcome(findings=findings, errors=errors)


def _parse_rule(raw_rule: dict[str, Any], index: int) -> SuppressionRule:
    rule_id = str(raw_rule.get("id", "")).strip()
    reason = str(raw_rule.get("reason", "")).strip()
    selectors_value = raw_rule.get("selectors")
    if not rule_id:
        raise ValueError(f"Suppression {index} is missing id")
    if not reason:
        raise ValueError(f"Suppression {rule_id!r} is missing reason")
    if not isinstance(selectors_value, dict) or not selectors_value:
        raise ValueError(f"Suppression {rule_id!r} requires selectors")
    unknown = set(selectors_value) - _SELECTORS
    if unknown:
        raise ValueError(f"Suppression {rule_id!r} has unsupported selectors: {sorted(unknown)}")
    selectors = {key: str(value).strip() for key, value in selectors_value.items() if str(value).strip()}
    if not selectors:
        raise ValueError(f"Suppression {rule_id!r} requires non-empty selectors")
    expires_at = None
    expires = raw_rule.get("expires_at")
    if expires:
        try:
            expires_at = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Suppression {rule_id!r} has invalid expires_at") from exc
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
    return SuppressionRule(rule_id=rule_id, reason=reason, selectors=selectors, expires_at=expires_at)


def _matches(finding: Finding, selectors: dict[str, str]) -> bool:
    actual = {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "vulnerability_type": finding.vulnerability_type,
        "resource": normalize_resource(finding.resource),
        "endpoint": normalize_endpoint(finding.endpoint),
        "scanner": ",".join(finding.sources or [finding.scanner]),
    }
    for key, expected in selectors.items():
        if key == "scanner":
            if not any(fnmatchcase(source.casefold(), expected.casefold()) for source in finding.sources):
                return False
            continue
        candidate = actual[key]
        pattern = expected
        if key == "resource":
            pattern = normalize_resource(expected)
        elif key == "endpoint":
            pattern = normalize_endpoint(expected)
        if not fnmatchcase(candidate.casefold(), pattern.casefold()):
            return False
    return True
