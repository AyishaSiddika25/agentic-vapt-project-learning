"""Normalized models shared by every Agentic VAPT pipeline stage."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_value(cls, value: object) -> Severity:
        normalized = str(value or "").strip().lower()
        aliases = {
            "none": cls.INFO,
            "note": cls.LOW,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "error": cls.HIGH,
        }
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNKNOWN


class Validity(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class SuppressionStatus(StrEnum):
    ACTIVE = "active"
    SUPPRESSED = "suppressed"


class Reachability(StrEnum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class GateDecision(StrEnum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"
    SUPPRESSED = "suppressed"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class Location:
    resource: str = ""
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    uri: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "uri": self.uri,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass(slots=True)
class Finding:
    scanner: str
    rule_id: str
    title: str
    description: str = ""
    vulnerability_type: str = ""
    severity: Severity = Severity.UNKNOWN
    confidence: float | None = None
    resource: str = ""
    locations: list[Location] = field(default_factory=list)
    endpoint: str = ""
    evidence: list[str] = field(default_factory=list)
    fingerprint: str = ""
    internal_id: str = ""
    suppression_status: SuppressionStatus = SuppressionStatus.ACTIVE
    suppression_reason: str = ""
    suppression_rule_id: str = ""
    reachability: Reachability = Reachability.UNKNOWN
    reachability_reason: str = ""
    validity: Validity = Validity.UNKNOWN
    validation_errors: list[str] = field(default_factory=list)
    risk_score: float | None = None
    decision: GateDecision = GateDecision.UNKNOWN
    decision_reasons: list[str] = field(default_factory=list)
    remediation: str = ""
    sources: list[str] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def primary_location(self) -> Location:
        if self.locations:
            return self.locations[0]
        return Location(resource=self.resource, uri=self.resource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "internal_id": self.internal_id,
            "scanner": self.scanner,
            "sources": self.sources or [self.scanner],
            "rule_id": self.rule_id,
            "vulnerability_type": self.vulnerability_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "resource": self.resource,
            "locations": [location.to_dict() for location in self.locations],
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
            "suppression_status": self.suppression_status.value,
            "suppression_reason": self.suppression_reason,
            "suppression_rule_id": self.suppression_rule_id,
            "reachability": self.reachability.value,
            "reachability_reason": self.reachability_reason,
            "validity": self.validity.value,
            "validation_errors": self.validation_errors,
            "risk_score": self.risk_score,
            "decision": self.decision.value,
            "decision_reasons": self.decision_reasons,
            "remediation": self.remediation,
            "raw_metadata": self.raw_metadata,
            "timestamp": self.timestamp,
        }
