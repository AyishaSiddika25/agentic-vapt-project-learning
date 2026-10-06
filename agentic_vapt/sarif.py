"""Fault-tolerant SARIF 2.x normalization into the common finding model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Finding, Location, Severity


@dataclass(slots=True)
class NormalizationResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def normalize_sarif(document: object) -> NormalizationResult:
    outcome = NormalizationResult()
    if not isinstance(document, dict):
        outcome.errors.append("SARIF root must be an object")
        return outcome
    version = document.get("version")
    if not isinstance(version, str) or not version.startswith("2."):
        outcome.errors.append(f"Unsupported or missing SARIF version: {version!r}")
        return outcome
    runs = document.get("runs")
    if not isinstance(runs, list):
        outcome.errors.append("SARIF runs must be a list")
        return outcome
    outcome.metadata = {
        "version": version,
        "run_count": len(runs),
        "schema": document.get("$schema", ""),
    }

    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            outcome.errors.append(f"Run {run_index} is not an object")
            continue
        try:
            _normalize_run(run, run_index, outcome)
        except (AttributeError, TypeError, ValueError) as exc:
            outcome.errors.append(f"Run {run_index} could not be normalized: {exc}")
    return outcome


def _normalize_run(run: dict[str, Any], run_index: int, outcome: NormalizationResult) -> None:
    driver = _mapping(_mapping(run.get("tool")).get("driver"))
    scanner = _text(driver.get("name")) or "unknown"
    tool_metadata = {
        "name": scanner,
        "version": _text(driver.get("version")) or _text(driver.get("semanticVersion")),
        "information_uri": _text(driver.get("informationUri")),
    }
    rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
    rules_by_id = {
        _text(rule.get("id")): rule for rule in rules if isinstance(rule, dict) and _text(rule.get("id"))
    }
    results = run.get("results")
    if results is None:
        results = []
    if not isinstance(results, list):
        outcome.errors.append(f"Run {run_index} results must be a list")
        return

    for result_index, raw_result in enumerate(results):
        if not isinstance(raw_result, dict):
            outcome.errors.append(f"Run {run_index} result {result_index} is not an object")
            continue
        try:
            finding = _normalize_result(raw_result, scanner, tool_metadata, rules, rules_by_id)
        except (AttributeError, TypeError, ValueError) as exc:
            outcome.errors.append(f"Run {run_index} result {result_index} was skipped: {exc}")
            continue
        outcome.findings.append(finding)


def _normalize_result(
    result: dict[str, Any],
    scanner: str,
    tool_metadata: dict[str, str],
    rules: list[object],
    rules_by_id: dict[str, dict[str, Any]],
) -> Finding:
    rule_id = _text(result.get("ruleId"))
    rule_index = result.get("ruleIndex")
    rule: dict[str, Any] = rules_by_id.get(rule_id, {})
    if (
        not rule
        and isinstance(rule_index, int)
        and not isinstance(rule_index, bool)
        and 0 <= rule_index < len(rules)
    ):
        candidate = rules[rule_index]
        if isinstance(candidate, dict):
            rule = candidate
            rule_id = rule_id or _text(rule.get("id"))

    result_properties = _mapping(result.get("properties"))
    rule_properties = _mapping(rule.get("properties"))
    message = _message(result.get("message"))
    title = _message(rule.get("shortDescription")) or message or rule_id or "Untitled security finding"
    description = _message(rule.get("fullDescription")) or message
    level = _text(result.get("level")) or _text(_mapping(rule.get("defaultConfiguration")).get("level"))
    severity = _severity(level, result_properties, rule_properties)
    locations = _locations(result.get("locations"))
    resource = locations[0].resource if locations else ""
    endpoint = _first_text(result_properties, "endpoint", "url", "request_url")
    vulnerability_type = _vulnerability_type(result_properties, rule_properties)
    evidence = _evidence(result, message)
    confidence = _confidence(result_properties.get("confidence"))
    raw_fingerprints = result.get("fingerprints") if isinstance(result.get("fingerprints"), dict) else {}

    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        title=title,
        description=description,
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence=confidence,
        resource=resource,
        locations=locations,
        endpoint=endpoint,
        evidence=evidence,
        remediation=_message(rule.get("help")),
        sources=[scanner],
        raw_metadata={
            "tool": tool_metadata,
            "rule": rule,
            "result": result,
            "sarif_fingerprints": raw_fingerprints,
            "help_uri": _text(rule.get("helpUri")),
        },
    )


def _locations(value: object) -> list[Location]:
    if not isinstance(value, list):
        return []
    locations: list[Location] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        physical = _mapping(item.get("physicalLocation"))
        artifact = _mapping(physical.get("artifactLocation"))
        region = _mapping(physical.get("region"))
        uri = _text(artifact.get("uri"))
        logical = item.get("logicalLocations")
        logical_name = ""
        if isinstance(logical, list) and logical and isinstance(logical[0], dict):
            logical_name = _text(logical[0].get("fullyQualifiedName")) or _text(logical[0].get("name"))
        locations.append(
            Location(
                resource=uri or logical_name,
                uri=uri,
                start_line=_positive_integer(region.get("startLine")),
                start_column=_positive_integer(region.get("startColumn")),
                end_line=_positive_integer(region.get("endLine")),
                end_column=_positive_integer(region.get("endColumn")),
            )
        )
    return locations


def _evidence(result: dict[str, Any], message: str) -> list[str]:
    values: list[str] = []
    if message:
        values.append(message)
    for location in result.get("locations", []) if isinstance(result.get("locations"), list) else []:
        if not isinstance(location, dict):
            continue
        region = _mapping(_mapping(location.get("physicalLocation")).get("region"))
        snippet = _message(region.get("snippet"))
        if snippet:
            values.append(snippet)
    return list(dict.fromkeys(values))


def _severity(level: str, result_properties: dict[str, Any], rule_properties: dict[str, Any]) -> Severity:
    explicit = _first_text(result_properties, "severity") or _first_text(rule_properties, "severity")
    if explicit:
        return Severity.from_value(explicit)
    security_score = result_properties.get("security-severity", rule_properties.get("security-severity"))
    try:
        score = float(security_score)
    except (TypeError, ValueError):
        return Severity.from_value(level)
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


def _vulnerability_type(*property_sets: dict[str, Any]) -> str:
    for properties in property_sets:
        direct = _first_text(properties, "vulnerability_type", "vulnerabilityType", "cwe")
        if direct:
            return direct
        tags = properties.get("tags")
        if isinstance(tags, list):
            for tag in tags:
                text = _text(tag)
                if text.upper().startswith("CWE-"):
                    return text.upper()
    return ""


def _confidence(value: object) -> float | None:
    labels = {"low": 0.3, "medium": 0.6, "high": 0.9}
    if isinstance(value, str) and value.lower() in labels:
        return labels[value.lower()]
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    if confidence > 1 and confidence <= 100:
        confidence /= 100
    return confidence if 0 <= confidence <= 1 else None


def _message(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return _text(value.get("text")) or _text(value.get("markdown")) or _text(value.get("id"))
    return ""


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _first_text(values: dict[str, Any], *keys: str) -> str:
    for key in keys:
        text = _text(values.get(key))
        if text:
            return text
    return ""


def _positive_integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None
