"""Finding validation that records errors without aborting an assessment."""

from __future__ import annotations

from .models import Finding, Validity


def validate_finding(finding: Finding) -> Finding:
    errors: list[str] = []
    if not finding.scanner.strip():
        errors.append("scanner is missing")
    if not finding.rule_id.strip() and not finding.vulnerability_type.strip():
        errors.append("rule_id and vulnerability_type are both missing")
    if not finding.title.strip():
        errors.append("title is missing")
    location = finding.primary_location
    for name, value in (
        ("start_line", location.start_line),
        ("start_column", location.start_column),
        ("end_line", location.end_line),
        ("end_column", location.end_column),
    ):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
            errors.append(f"{name} must be a positive integer")
    if (
        location.start_line is not None
        and location.end_line is not None
        and location.end_line < location.start_line
    ):
        errors.append("end_line precedes start_line")
    if finding.confidence is not None and not 0 <= finding.confidence <= 1:
        errors.append("confidence must be between 0 and 1")
    finding.validation_errors = errors
    finding.validity = Validity.INVALID if errors else Validity.VALID
    return finding
