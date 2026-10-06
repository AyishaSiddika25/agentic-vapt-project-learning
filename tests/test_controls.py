from __future__ import annotations

import unittest

from agentic_vapt.config import GatePolicy
from agentic_vapt.deduplication import deduplicate_findings
from agentic_vapt.fingerprint import assign_identity, create_fingerprint
from agentic_vapt.gate import evaluate_finding
from agentic_vapt.models import (
    GateDecision,
    Reachability,
    Severity,
    SuppressionStatus,
    Validity,
)
from agentic_vapt.reachability import evaluate_reachability
from agentic_vapt.suppression import apply_suppressions
from agentic_vapt.validation import validate_finding
from tests.helpers import make_finding


class FingerprintAndDeduplicationTests(unittest.TestCase):
    def test_fingerprint_is_deterministic_and_path_normalized(self) -> None:
        first = make_finding(resource="SRC\\Login.py")
        second = make_finding(resource="src/login.py")
        self.assertEqual(create_fingerprint(first), create_fingerprint(second))

    def test_cross_scanner_same_vulnerability_has_same_fingerprint(self) -> None:
        first = make_finding(scanner="Semgrep", rule_id="semgrep.sql")
        second = make_finding(scanner="CodeQL", rule_id="py/sql-query-built-from-user-controlled-sources")
        self.assertEqual(create_fingerprint(first), create_fingerprint(second))

    def test_different_location_has_different_fingerprint(self) -> None:
        self.assertNotEqual(
            create_fingerprint(make_finding(line=10)),
            create_fingerprint(make_finding(line=11)),
        )

    def test_similar_but_different_vulnerability_is_not_merged(self) -> None:
        first = make_finding(vulnerability_type="CWE-89")
        second = make_finding(vulnerability_type="CWE-78")
        self.assertEqual(len(deduplicate_findings([first, second])), 2)

    def test_exact_duplicates_are_merged(self) -> None:
        self.assertEqual(len(deduplicate_findings([make_finding(), make_finding()])), 1)

    def test_cross_scanner_merge_preserves_sources_and_strongest_severity(self) -> None:
        low = make_finding(scanner="Semgrep", severity=Severity.MEDIUM)
        high = make_finding(scanner="CodeQL", severity=Severity.CRITICAL)
        merged = deduplicate_findings([low, high])[0]
        self.assertEqual(merged.severity, Severity.CRITICAL)
        self.assertEqual(merged.sources, ["CodeQL", "Semgrep"])
        self.assertEqual(len(merged.raw_metadata["correlated_findings"]), 1)

    def test_missing_optional_fields_can_be_fingerprinted(self) -> None:
        finding = make_finding(resource="", line=None)
        finding.vulnerability_type = ""
        assign_identity(finding)
        self.assertEqual(len(finding.fingerprint), 64)


class SuppressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = assign_identity(make_finding())

    def test_fingerprint_suppression(self) -> None:
        rules = (
            {
                "id": "accepted",
                "reason": "risk accepted",
                "selectors": {"fingerprint": self.finding.fingerprint},
            },
        )
        outcome = apply_suppressions([self.finding], rules)
        self.assertEqual(outcome.findings[0].suppression_status, SuppressionStatus.SUPPRESSED)

    def test_rule_suppression_is_traceable(self) -> None:
        rules = (
            {
                "id": "test-only",
                "reason": "fixture",
                "selectors": {"rule_id": "python.*"},
            },
        )
        suppressed = apply_suppressions([self.finding], rules).findings[0]
        self.assertEqual(suppressed.suppression_rule_id, "test-only")
        self.assertEqual(suppressed.suppression_reason, "fixture")

    def test_non_matching_finding_remains_active(self) -> None:
        rules = (
            {
                "id": "other",
                "reason": "other",
                "selectors": {"rule_id": "javascript.*"},
            },
        )
        active = apply_suppressions([self.finding], rules).findings[0]
        self.assertEqual(active.suppression_status, SuppressionStatus.ACTIVE)

    def test_scanner_selector_matches_any_correlated_source(self) -> None:
        self.finding.sources = ["CodeQL", "Semgrep"]
        rules = ({"id": "source", "reason": "source rule", "selectors": {"scanner": "CodeQL"}},)
        suppressed = apply_suppressions([self.finding], rules).findings[0]
        self.assertEqual(suppressed.suppression_status, SuppressionStatus.SUPPRESSED)

    def test_invalid_rule_is_reported(self) -> None:
        outcome = apply_suppressions([self.finding], ({"id": "broken", "selectors": {}},))
        self.assertTrue(outcome.errors)
        self.assertEqual(self.finding.suppression_status, SuppressionStatus.ACTIVE)


class ReachabilityTests(unittest.TestCase):
    def test_reachable(self) -> None:
        finding = make_finding()
        finding.raw_metadata = {"properties": {"reachable": True}}
        self.assertEqual(evaluate_reachability(finding).reachability, Reachability.REACHABLE)

    def test_unreachable_requires_explicit_evidence(self) -> None:
        finding = make_finding()
        finding.raw_metadata = {
            "properties": {
                "reachability": "unreachable",
                "unreachable_reason": "dead code",
            }
        }
        evaluated = evaluate_reachability(finding)
        self.assertEqual(evaluated.reachability, Reachability.UNREACHABLE)
        self.assertEqual(evaluated.reachability_reason, "dead code")

    def test_unknown(self) -> None:
        self.assertEqual(evaluate_reachability(make_finding()).reachability, Reachability.UNKNOWN)

    def test_missing_information_is_unknown_not_unreachable(self) -> None:
        finding = make_finding()
        finding.raw_metadata = {"properties": {"unreachable_reason": "unsupported without status"}}
        self.assertEqual(evaluate_reachability(finding).reachability, Reachability.UNKNOWN)


class SecurityGateTests(unittest.TestCase):
    policy = GatePolicy()

    def prepared(self, severity: Severity, reachability: Reachability) -> object:
        finding = make_finding(severity=severity)
        validate_finding(finding)
        finding.reachability = reachability
        return finding

    def test_low_risk_passes(self) -> None:
        finding = self.prepared(Severity.LOW, Reachability.REACHABLE)
        self.assertEqual(evaluate_finding(finding, self.policy).decision, GateDecision.PASS)

    def test_high_reachable_blocks(self) -> None:
        finding = self.prepared(Severity.HIGH, Reachability.REACHABLE)
        self.assertEqual(evaluate_finding(finding, self.policy).decision, GateDecision.BLOCK)

    def test_high_unknown_reachability_warns_by_default(self) -> None:
        finding = self.prepared(Severity.HIGH, Reachability.UNKNOWN)
        self.assertEqual(evaluate_finding(finding, self.policy).decision, GateDecision.WARN)

    def test_policy_can_block_unknown_reachability(self) -> None:
        finding = self.prepared(Severity.HIGH, Reachability.UNKNOWN)
        strict_policy = GatePolicy(block_unknown_reachability=True)
        self.assertEqual(evaluate_finding(finding, strict_policy).decision, GateDecision.BLOCK)

    def test_suppressed_is_auditable(self) -> None:
        finding = self.prepared(Severity.CRITICAL, Reachability.REACHABLE)
        finding.suppression_status = SuppressionStatus.SUPPRESSED
        finding.suppression_rule_id = "accepted"
        finding.suppression_reason = "approved"
        self.assertEqual(evaluate_finding(finding, self.policy).decision, GateDecision.SUPPRESSED)

    def test_unreachable_passes_but_remains_a_finding(self) -> None:
        finding = self.prepared(Severity.CRITICAL, Reachability.UNREACHABLE)
        evaluated = evaluate_finding(finding, self.policy)
        self.assertEqual(evaluated.decision, GateDecision.PASS)
        self.assertTrue(evaluated.decision_reasons)

    def test_unknown_severity_is_unknown(self) -> None:
        finding = self.prepared(Severity.UNKNOWN, Reachability.UNKNOWN)
        self.assertEqual(evaluate_finding(finding, self.policy).decision, GateDecision.UNKNOWN)

    def test_invalid_finding_is_unknown(self) -> None:
        finding = make_finding()
        finding.validity = Validity.INVALID
        finding.validation_errors = ["bad location"]
        self.assertEqual(evaluate_finding(finding, self.policy).decision, GateDecision.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
