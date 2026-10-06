"""Shared test fixtures."""

from __future__ import annotations

from typing import Any

from agentic_vapt.models import Finding, Location, Severity


def make_finding(
    *,
    scanner: str = "Semgrep",
    rule_id: str = "python.sql-injection",
    vulnerability_type: str = "CWE-89",
    resource: str = "src/login.py",
    line: int | None = 10,
    severity: Severity = Severity.HIGH,
) -> Finding:
    locations = (
        [Location(resource=resource, uri=resource, start_line=line, end_line=line)] if resource else []
    )
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        vulnerability_type=vulnerability_type,
        title="Possible SQL injection",
        description="User input reaches a SQL query.",
        severity=severity,
        confidence=0.8,
        resource=resource,
        locations=locations,
        evidence=["query = 'SELECT' + user_input"],
        sources=[scanner],
    )


def make_sarif(
    *,
    tool: str = "Semgrep",
    rule_id: str = "python.sql-injection",
    vulnerability_type: str = "CWE-89",
    resource: str = "src/login.py",
    line: int = 10,
    level: str = "error",
    reachability: str | None = "reachable",
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "vulnerability_type": vulnerability_type,
        "confidence": "high",
    }
    if reachability is not None:
        properties["reachability"] = reachability
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool,
                        "version": "1.0",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": "Possible SQL injection"},
                                "fullDescription": {"text": "Untrusted input may reach SQL."},
                                "defaultConfiguration": {"level": level},
                                "properties": {"tags": [vulnerability_type]},
                                "help": {"text": "Use parameterized queries."},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {"text": "Possible SQL injection"},
                        "properties": properties,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": resource},
                                    "region": {
                                        "startLine": line,
                                        "startColumn": 5,
                                        "endLine": line,
                                        "endColumn": 30,
                                        "snippet": {"text": "query = 'SELECT' + user_input"},
                                    },
                                }
                            }
                        ],
                        "fingerprints": {"scanner/v1": "scanner-owned-fingerprint"},
                    }
                ],
            }
        ],
    }
