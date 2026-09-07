# Day 7 – Finding Identity, Deduplication & Initial Gating

## Objective

The objective of Day 7 is to understand how security findings can be uniquely identified, deduplicated, and initially gated before they move to the next stage of the AGENTC VAPT pipeline.

Day 6 established the:

```text
Semgrep
   ↓
SARIF
   ↓
Normalized Finding

Day 7 builds the next Engineer 2 capability:

Normalized Findings
        ↓
Finding Identity
        ↓
Fingerprint Generation
        ↓
Deduplication
        ↓
Initial Gating
        ↓
Findings for Further Analysis

This work is part of the Detection, Gating and Rule Lifecycle responsibility of Engineer 2.

1. Engineer 2 Responsibility

According to the AGENTC VAPT four-engineer production plan, Engineer 2 owns:

Detection
Gating
Finding fingerprinting
Deduplication
Suppression
Reachability analysis
Scanner integrations
SARIF normalization
Security rule lifecycle

The production plan specifically requires:

Stable finding fingerprints
Deduplication
Reversible suppressions
Initial gating
Reachability ranking
Rule generation and regression testing

Day 7 focuses on the first part of this area:

Finding Fingerprinting
        +
Deduplication
        +
Initial Gating
2. Why Finding Identity Is Required

Security scanners may report the same vulnerability multiple times.

For example, a scanner may report:

Rule: python.sql-injection
File: login.py
Line: 10

If the same application is scanned again, the same finding may appear again.

Without a stable identity, the system may treat it as a completely new finding.

This can result in:

Duplicate findings
Incorrect finding counts
Repeated notifications
Unnecessary triage
Difficulty tracking a vulnerability across scans

Therefore, AGENTC VAPT needs a stable way to identify a finding.

3. Finding Identity

For the Day 7 implementation, the finding identity is created using:

rule_id
+
file
+
line

Example:

python.sql-injection|login.py|10

This represents the identity of the finding.

The identity is then converted into a SHA-256 hash to create a fingerprint.

Finding Identity
       ↓
python.sql-injection|login.py|10
       ↓
SHA-256
       ↓
Finding Fingerprint
4. Finding Fingerprint

A fingerprint is a unique identifier generated from the important properties of a finding.

Example:

Rule ID:
python.sql-injection

File:
login.py

Line:
10

Identity:

python.sql-injection|login.py|10

Fingerprint:

SHA-256(identity)

The exact SHA-256 value is not important for the learning exercise.

The important concept is:

Same finding
     ↓
Same identity
     ↓
Same fingerprint

Therefore, the system can recognize that two records represent the same finding.

5. Example Findings

For the Day 7 exercise, a sample finding file is used.

sample_findings.json

[
    {
        "rule_id": "python.sql-injection",
        "file": "login.py",
        "line": 10,
        "severity": "high",
        "message": "Possible SQL injection"
    },
    {
        "rule_id": "python.sql-injection",
        "file": "login.py",
        "line": 10,
        "severity": "high",
        "message": "Possible SQL injection"
    },
    {
        "rule_id": "python.hardcoded-password",
        "file": "config.py",
        "line": 5,
        "severity": "medium",
        "message": "Possible hardcoded password"
    }
]

The first two findings have the same:

rule_id
file
line

Therefore, they should receive the same fingerprint.

They are treated as duplicates.

6. Project Structure

The Day 7 directory contains:

Day-07/
│
├── README.md
├── sample_findings.json
├── fingerprint.py
├── deduplicate.py
└── gate_findings.py
File description
File	Purpose
README.md	Day 7 documentation
sample_findings.json	Sample security findings
fingerprint.py	Generates finding fingerprints
deduplicate.py	Identifies duplicate findings
gate_findings.py	Performs initial gating
7. Coding Practice 1 – Fingerprint Generation
File
fingerprint.py
Code
import hashlib


def create_fingerprint(finding):
    identity = (
        f"{finding['rule_id']}|"
        f"{finding['file']}|"
        f"{finding['line']}"
    )

    fingerprint = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()

    return fingerprint


finding = {
    "rule_id": "python.sql-injection",
    "file": "login.py",
    "line": 10
}

print("Finding identity:")
print(
    f"{finding['rule_id']}|"
    f"{finding['file']}|"
    f"{finding['line']}"
)

print("\nFingerprint:")
print(create_fingerprint(finding))
8. Running the Fingerprint Program

Run the following command from the repository root:

python Day-07\fingerprint.py

Expected output:

Finding identity:
python.sql-injection|login.py|10

Fingerprint:
<64-character SHA-256 hash>

The fingerprint is generated using Python's built-in hashlib module.

No external package is required for this particular exercise.

9. Coding Practice 2 – Deduplication
File
deduplicate.py

The program reads the sample findings and creates fingerprints for every finding.

It then checks whether the fingerprint already exists.

If the fingerprint already exists:

Duplicate

Otherwise:

New / Unique Finding
Code
import json
from fingerprint import create_fingerprint


with open("Day-07/sample_findings.json", "r", encoding="utf-8") as file:
    findings = json.load(file)


unique_findings = {}
duplicates = []


for finding in findings:
    fingerprint = create_fingerprint(finding)

    finding["fingerprint"] = fingerprint

    if fingerprint in unique_findings:
        duplicates.append(finding)
    else:
        unique_findings[fingerprint] = finding


print("Total findings:", len(findings))
print("Unique findings:", len(unique_findings))
print("Duplicates:", len(duplicates))

print("\nUnique Findings:")

for finding in unique_findings.values():
    print(
        f"- {finding['rule_id']} "
        f"{finding['file']}:{finding['line']}"
    )
10. Running Deduplication

Run:

python Day-07\deduplicate.py

Expected output:

Total findings: 3
Unique findings: 2
Duplicates: 1

Unique Findings:
- python.sql-injection login.py:10
- python.hardcoded-password config.py:5

This demonstrates that:

3 scanner records
       ↓
2 unique findings
       ↓
1 duplicate removed from active processing

The original finding does not need to be forgotten or destroyed. In a production system, finding history and decisions should remain traceable.

11. Why Deduplication Is Important

Without deduplication:

Finding A
Finding A
Finding A
Finding B
Finding B

The system may treat these as five separate findings.

After deduplication:

Finding A
Finding B

This provides a cleaner finding set for later stages.

It also reduces unnecessary:

Triage
Model calls
Validation attempts
Notifications
Review effort
12. Coding Practice 3 – Initial Gating

After deduplication, findings need to be evaluated to determine whether they should continue through the pipeline.

This is called gating.

For the Day 7 learning exercise, the simple policy is:

High severity   → KEEP
Medium severity → KEEP
Low severity    → FILTER

This is only a simplified demonstration.

The production AGENTC VAPT system should use explicit, controlled policy and preserve the decision trail.

13. Initial Gating Flow
Unique Finding
      ↓
Check Severity
      ↓
 ┌───────────────┐
 │ Severity      │
 └───────┬───────┘
         │
    ┌────┴────┐
    ↓         ↓
 High/Medium  Low
    ↓         ↓
   KEEP      FILTER
14. gate_findings.py
Code
import json
from fingerprint import create_fingerprint


with open("Day-07/sample_findings.json", "r", encoding="utf-8") as file:
    findings = json.load(file)


for finding in findings:
    finding["fingerprint"] = create_fingerprint(finding)


unique_findings = {}

for finding in findings:
    fingerprint = finding["fingerprint"]

    if fingerprint not in unique_findings:
        unique_findings[fingerprint] = finding


print("Initial Gate Results:\n")


for finding in unique_findings.values():

    severity = finding["severity"]

    if severity in ["high", "medium"]:
        decision = "KEEP"
    else:
        decision = "FILTER"

    print(
        f"{finding['rule_id']} | "
        f"{finding['file']}:{finding['line']} | "
        f"{severity} | "
        f"{decision}"
    )
15. Running Initial Gating

Run:

python Day-07\gate_findings.py

Expected output:

Initial Gate Results:

python.sql-injection | login.py:10 | high | KEEP
python.hardcoded-password | config.py:5 | medium | KEEP

Both findings continue because their severity is either:

high

or:

medium
16. Complete Day 7 Pipeline

The complete learning implementation is:

                  Security Scanner
                        │
                        ▼
                Normalized Findings
                        │
                        ▼
              ┌───────────────────┐
              │ Finding Identity   │
              └─────────┬─────────┘
                        │
                        ▼
                 Fingerprint
                        │
                        ▼
              ┌───────────────────┐
              │  Deduplication    │
              └─────────┬─────────┘
                        │
                        ▼
                Unique Findings
                        │
                        ▼
              ┌───────────────────┐
              │  Initial Gating   │
              └─────────┬─────────┘
                        │
                  ┌─────┴─────┐
                  ▼           ▼
                KEEP        FILTER
                  │
                  ▼
             Next Stage
                Triage
17. Relationship With Day 6

Day 6 focused on transforming scanner results into a normalized representation.

Day 6

Semgrep
   ↓
SARIF
   ↓
Normalized Finding

Day 7 continues from that point:

Day 7

Normalized Finding
   ↓
Fingerprint
   ↓
Deduplication
   ↓
Initial Gating

Therefore:

Day 6 + Day 7

Scanner
   ↓
SARIF
   ↓
Normalized Finding
   ↓
Fingerprint
   ↓
Deduplication
   ↓
Gating
   ↓
Triage

This creates the foundation for the later AGENTC VAPT pipeline.

18. Important Difference Between Filtering and Deleting

Gating should not simply mean:

"Delete findings we don't want."

Instead, the system should make a traceable decision:

Finding
   ↓
Decision
   ↓
Reason
   ↓
State

For example:

Finding:
python.sql-injection

Decision:
KEEP

Reason:
High severity

State:
Active

Or:

Finding:
example-rule

Decision:
FILTER

Reason:
Policy condition

State:
Filtered

In the production design, filtering and suppression must remain visible, reversible, and auditable.

19. Finding Lifecycle

The Day 7 concepts contribute to a larger finding lifecycle:

Detected
   ↓
Normalized
   ↓
Fingerprint Generated
   ↓
Deduplicated
   ↓
Gated
   ↓
Triage
   ↓
Validation
   ↓
Human Review
   ↓
Confirmed / Rejected / Accepted Risk

The model must not independently suppress or close findings.

Human control remains part of the production design.

20. Security Considerations

Finding identity must be designed carefully in a production system.

A fingerprint should not rely only on information that can change unnecessarily.

For example, using only:

line number

could be unstable.

If code moves from:

line 10

to:

line 15

the same vulnerability might receive a different fingerprint.

Therefore, the production fingerprint specification will need to consider stable attributes and repository context.

The Day 7 implementation intentionally uses:

rule_id + file + line

as a simple learning model.

It is not the final production fingerprint specification.

21. Connection to AGENTC VAPT

The four-engineer production plan assigns Engineer 2 responsibility for:

Scanner Integration
       ↓
SARIF Normalization
       ↓
Finding Fingerprinting
       ↓
Deduplication
       ↓
Gating
       ↓
Reachability
       ↓
Rule Lifecycle

Day 7 implements the middle portion of this flow:

Finding
   ↓
Fingerprint
   ↓
Deduplication
   ↓
Initial Gate

This will later connect with:

Joern reachability
Suppression
Triage
Rule generation
Regression testing
22. What I Learned Today
Finding Identity

I learned how security findings can be represented using stable identifying attributes.

Fingerprinting

I learned how a SHA-256 hash can be used to create a compact fingerprint for a finding.

Deduplication

I learned how fingerprints can be compared to identify duplicate findings.

Gating

I learned how findings can be evaluated against an initial policy before continuing through the security pipeline.

Pipeline Design

I understood that detection should not immediately lead to model analysis. Findings should first pass through deterministic processing such as:

Normalization
   ↓
Fingerprinting
   ↓
Deduplication
   ↓
Gating
23. Day 7 Key Takeaways

The main concepts learned today are:

Finding identity
Finding fingerprints
SHA-256 hashing
Duplicate detection
Unique finding storage
Initial gating
KEEP / FILTER decisions
Finding lifecycle
Traceable security decisions
Deterministic preprocessing
24. Production Relevance

The Day 7 work directly contributes to Engineer 2's production responsibilities.

The production system needs:

Stable Finding Identity
        ↓
Reliable Deduplication
        ↓
Controlled Gating
        ↓
Accurate Triage Input

This prevents the AI/validation stages from unnecessarily processing repeated findings.

It also creates the foundation for future capabilities such as:

Fingerprint
    ↓
Suppression
    ↓
Reachability Ranking
    ↓
Triage
    ↓
Validation
25. Day 7 Status

Status: Completed

Completed
 Understood finding identity
 Implemented finding fingerprint generation
 Used SHA-256 for fingerprints
 Created sample security findings
 Implemented duplicate detection
 Implemented initial gating
 Tested the complete Day 7 flow
 Connected Day 7 with the Day 6 SARIF normalization pipeline
 Connected the work to Engineer 2 responsibilities
26. Final Day 7 Architecture
                 AGENTC VAPT
                      │
                      ▼
              Security Scanners
                      │
                      ▼
                  SARIF
                      │
                      ▼
           Normalized Finding
                      │
                      ▼
            Finding Fingerprint
                      │
                      ▼
              Deduplication
                      │
                      ▼
              Initial Gating
                      │
                ┌─────┴─────┐
                ▼           ▼
              KEEP        FILTER
                │
                ▼
              Triage
                │
                ▼
            Validation
                │
                ▼
          Human Review
Conclusion

Day 7 extended the deterministic detection pipeline by introducing finding identity, fingerprinting, deduplication, and initial gating.

The main concept learned was that a security scanner finding should not immediately become a separate vulnerability record. The system first needs to determine:

What finding is this?
        ↓
Have we already seen it?
        ↓
Should it continue?

This provides a clean and deterministic foundation for the later AGENTC VAPT stages, including AI triage, reachability analysis, exploit validation, and rule lifecycle management.
