"""Stable, scanner-neutral finding identity.

The correlation fingerprint is SHA-256 over the canonical vulnerability type (or
rule ID when no type is available), normalized resource, primary start line, and
normalized endpoint. Scanner names, timestamps, messages, and volatile evidence
are deliberately excluded. Cross-scanner correlation therefore requires a shared
vulnerability type; otherwise the scanner rule ID remains part of identity.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .models import Finding


def normalize_resource(value: str) -> str:
    resource = unquote(str(value or "").strip()).replace("\\", "/")
    if resource.lower().startswith("file://"):
        resource = resource[7:]
    resource = re.sub(r"^[a-zA-Z]:/", "", resource)
    normalized = posixpath.normpath(resource) if resource else ""
    return "" if normalized == "." else normalized.lstrip("./").casefold()


def normalize_endpoint(value: str) -> str:
    endpoint = str(value or "").strip()
    if not endpoint:
        return ""
    parsed = urlsplit(endpoint)
    if parsed.scheme and parsed.netloc:
        return urlunsplit(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/"),
                parsed.query,
                "",
            )
        )
    return endpoint.rstrip("/").casefold()


def vulnerability_identity(finding: Finding) -> str:
    value = finding.vulnerability_type or finding.rule_id
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def create_fingerprint(finding: Finding) -> str:
    location = finding.primary_location
    payload = {
        "vulnerability": vulnerability_identity(finding),
        "resource": normalize_resource(finding.resource or location.resource or location.uri),
        "start_line": location.start_line,
        "endpoint": normalize_endpoint(finding.endpoint),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assign_identity(finding: Finding) -> Finding:
    finding.fingerprint = create_fingerprint(finding)
    finding.internal_id = f"av-{finding.fingerprint[:20]}"
    if not finding.sources:
        finding.sources = [finding.scanner]
    return finding
