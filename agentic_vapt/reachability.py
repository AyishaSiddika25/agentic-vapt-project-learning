"""Conservative reachability evaluation with an explicit UNKNOWN state."""

from __future__ import annotations

from typing import Any

from .models import Finding, Reachability


def evaluate_reachability(finding: Finding) -> Finding:
    properties = _properties(finding)
    explicit = properties.get("reachability")
    if isinstance(explicit, str):
        normalized = explicit.strip().lower()
        if normalized in {"reachable", "true", "yes"}:
            finding.reachability = Reachability.REACHABLE
            finding.reachability_reason = "Scanner supplied explicit reachable evidence."
            return finding
        if normalized in {
            "unreachable",
            "false",
            "no",
            "not_applicable",
            "not-applicable",
        }:
            finding.reachability = Reachability.UNREACHABLE
            finding.reachability_reason = _reason(
                properties, "Scanner supplied explicit unreachable evidence."
            )
            return finding
        if normalized == "unknown":
            finding.reachability = Reachability.UNKNOWN
            finding.reachability_reason = "Scanner reported unknown reachability."
            return finding

    reachable = properties.get("reachable")
    if reachable is True:
        finding.reachability = Reachability.REACHABLE
        finding.reachability_reason = "Scanner supplied reachable=true."
        return finding
    if reachable is False:
        finding.reachability = Reachability.UNREACHABLE
        finding.reachability_reason = _reason(properties, "Scanner supplied reachable=false.")
        return finding

    context = finding.raw_metadata.get("context")
    if (
        isinstance(context, dict)
        and context.get("user_input")
        and any(context.get(key) for key in ("database_operation", "command_execution", "external_endpoint"))
    ):
        finding.reachability = Reachability.REACHABLE
        finding.reachability_reason = "Context links user-controlled input to a security-sensitive operation."
        return finding

    finding.reachability = Reachability.UNKNOWN
    finding.reachability_reason = "No conclusive reachability evidence is available."
    return finding


def _properties(finding: Finding) -> dict[str, Any]:
    result = finding.raw_metadata.get("result")
    if isinstance(result, dict) and isinstance(result.get("properties"), dict):
        return result["properties"]
    properties = finding.raw_metadata.get("properties")
    return properties if isinstance(properties, dict) else {}


def _reason(properties: dict[str, Any], fallback: str) -> str:
    value = properties.get("reachability_reason") or properties.get("unreachable_reason")
    return str(value).strip() if isinstance(value, str) and value.strip() else fallback
