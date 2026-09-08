# Day 7 – Finding Fingerprinting, Deduplication & Initial Gating

## Objective

The objective of Day 7 was to build the next layer after the Day-6 Semgrep → SARIF → normalized finding pipeline.

The main focus was:

- Stable finding identity
- Finding fingerprints
- Duplicate detection
- Deduplication
- Initial severity-based gating
- Integration with the normalized finding format from Day 6

Day 7 extends the scanner pipeline instead of creating a separate finding format.

---

# 1. Day 6 → Day 7 Integration

Day 6 produces normalized security findings.

Day 7 consumes those normalized findings.

```text
Git Changes
     |
     v
Differential Analysis
     |
     v
Semgrep
     |
     v
SARIF 2.1.0
     |
     v
Finding Normalization
     |
     v
Stable Fingerprint
     |
     v
Day 7
     |
     +------------------+
     |                  |
     v                  v
Deduplication       Initial Gating
     |                  |
     +--------+---------+
              |
              v
      Findings for
      Further Analysis

This establishes the connection between the Day-6 scanner integration and the Day-7 finding-processing layer.

2. Normalized Finding Contract

Day 7 uses the same normalized finding structure established in Day 6.

{
    "scanner": "Semgrep",
    "rule_id": "example-rule",
    "message": "Security finding",
    "severity": "high",
    "file": "example.py",
    "start_line": 10,
    "start_column": 5,
    "end_line": 10,
    "end_column": 30,
    "fingerprint": "..."
}

Important fields include:

scanner
rule_id
message
severity
file
start_line
start_column
end_line
end_column
fingerprint

The Day-7 implementation therefore does not use the old line field.

It uses:

start_line
end_line

to remain compatible with Day 6.

3. Finding Identity

A security scanner may report the same underlying issue multiple times.

For example:

Finding 1
SQL Injection
login.py:10

Finding 2
SQL Injection
login.py:10

These findings represent the same finding location.

A stable identity is therefore required.

Day 6 already generates a deterministic fingerprint.

Day 7 reuses that fingerprint when it is available.

4. Fingerprint Generation

The fingerprint is based on:

Rule ID
+
Normalized File Path
+
Start Line
+
End Line

Conceptually:

Finding Information
        |
        v
Normalize File Path
        |
        v
Create Identity String
        |
        v
SHA-256
        |
        v
64-character fingerprint

Example:

rule-id|login.py|10|10

is converted into a SHA-256 hexadecimal fingerprint.

The same finding information produces the same fingerprint.

Different finding locations produce different fingerprints.

5. Why Fingerprinting is Important

Stable finding identity supports:

Deduplication
Finding tracking
Suppression
Historical comparison
Regression detection
Future reachability analysis
Future AI/LLM triage

Without a stable identity, downstream systems may treat the same finding as a new finding on every scan.

6. Deduplication

Deduplication removes repeated findings with the same fingerprint.

Example input:

Finding A → fingerprint-001
Finding B → fingerprint-001
Finding C → fingerprint-002

After deduplication:

fingerprint-001
fingerprint-002

Result:

Total findings: 3
Unique findings: 2
Duplicates: 1

The first occurrence of a fingerprint is retained.

7. Deduplication Workflow
Normalized Findings
        |
        v
Read Fingerprint
        |
        v
Already Seen?
     /     \
   Yes      No
    |        |
    v        v
Duplicate   Keep
    |        |
    +----+---+
         |
         v
Unique Findings
8. Initial Gating

After deduplication, findings can be passed through an initial security gate.

The Day-7 demonstration gate uses severity.

Current policy:

High   → KEEP
Medium → KEEP
Other  → FILTER

The purpose of this gate is to demonstrate deterministic finding filtering.

It is not the final production security decision.

9. Why Deduplication Happens Before Gating

The pipeline should avoid evaluating the same finding multiple times.

Therefore:

Normalized Findings
        |
        v
Fingerprint
        |
        v
Deduplication
        |
        v
Initial Gating

This ensures that the gate processes unique findings.

10. Example

Input:

[
    {
        "scanner": "Semgrep",
        "rule_id": "python.sql-injection",
        "severity": "high",
        "file": "login.py",
        "start_line": 10,
        "end_line": 10,
        "fingerprint": "demo-fingerprint-001"
    },
    {
        "scanner": "Semgrep",
        "rule_id": "python.sql-injection",
        "severity": "high",
        "file": "login.py",
        "start_line": 10,
        "end_line": 10,
        "fingerprint": "demo-fingerprint-001"
    },
    {
        "scanner": "Semgrep",
        "rule_id": "python.hardcoded-password",
        "severity": "medium",
        "file": "config.py",
        "start_line": 5,
        "end_line": 5,
        "fingerprint": "demo-fingerprint-002"
    }
]

Initial state:

Total findings: 3

After deduplication:

Unique findings: 2
Duplicates: 1

After gating:

python.sql-injection | login.py:10 | high | KEEP

python.hardcoded-password | config.py:5 | medium | KEEP
11. Files
Day-07/
├── README.md
├── sample_findings.json
├── fingerprint.py
├── deduplicate.py
└── gate_findings.py
12. File Responsibilities
fingerprint.py

Responsible for:

Reading normalized finding identity
Reusing an existing Day-6 fingerprint
Generating a compatible fingerprint when required
deduplicate.py

Responsible for:

Processing findings
Creating/reusing fingerprints
Detecting duplicates
Keeping the first occurrence
Returning unique findings
gate_findings.py

Responsible for:

Consuming deduplicated findings
Applying the initial severity-based gate
Producing a deterministic KEEP/FILTER decision
sample_findings.json

Provides controlled test data for:

Duplicate findings
Unique findings
Finding severity
Finding locations
Fingerprints
13. Commands

Run the deduplication demonstration:

python Day-07/deduplicate.py

Run the initial gate:

python Day-07/gate_findings.py

Run the Day-6 tests:

python -m unittest Day-06/test_semgrep_adapter.py -v
14. Expected Deduplication Output
Total findings: 3
Unique findings: 2
Duplicates: 1

Unique Findings:
- python.sql-injection login.py:10
  Fingerprint: demo-fingerprint-001

- python.hardcoded-password config.py:5
  Fingerprint: demo-fingerprint-002
15. Expected Gate Output
Initial Gate Results:

Total findings: 3
Unique findings: 2
Duplicates removed: 1

python.sql-injection | login.py:10 | high | KEEP
python.hardcoded-password | config.py:5 | medium | KEEP
16. Relevance to Agentic VAPT

Day 7 strengthens the detection and gating layer of the Agentic VAPT pipeline.

The overall direction is:

Changed Code
     |
     v
Security Scanners
     |
     v
SARIF / Normalization
     |
     v
Stable Fingerprint
     |
     v
Deduplication
     |
     v
Initial Gating
     |
     v
Future Suppression
     |
     v
Future Reachability
     |
     v
Future AI / LLM Triage

The current Day-7 gate is intentionally deterministic.

AI/LLM components are not given authority to modify or close findings at this stage.

17. Day 7 Key Learnings
1. Finding Identity

Learned why security findings require stable identities across scans.

2. Fingerprinting

Implemented deterministic SHA-256-based finding identity compatible with Day 6.

3. Deduplication

Learned how duplicate scanner findings can be detected using fingerprints.

4. Normalized Finding Contracts

Connected Day 7 to the normalized finding structure produced by Day 6.

5. Initial Gating

Implemented a deterministic severity-based KEEP/FILTER decision.

6. Pipeline Ordering

Established:

Fingerprint
    ↓
Deduplication
    ↓
Gating

rather than independently repeating finding-processing logic.

18. Day 7 Status

Status: Completed

Completed Work
Reviewed the Day-6 normalized finding contract
Identified and corrected the Day-6 test/fixture mismatch
Updated Day-7 to use start_line and end_line
Maintained the Day-6 fingerprint identity scheme
Implemented finding deduplication
Removed duplicate processing logic from the gate
Implemented initial severity-based gating
Created controlled sample findings
Connected Day-6 finding normalization with Day-7 processing
19. Final Day 6 → Day 7 Pipeline
                    Git Repository
                          |
                          v
                     Git Diff
                          |
                          v
                Changed Python Files
                          |
                          v
               Differential Analysis
                          |
                          v
                     Semgrep
                          |
                          v
                    SARIF 2.1.0
                          |
                          v
                Finding Normalization
                          |
                          v
                Stable Fingerprinting
                          |
                          v
                    Deduplication
                          |
                          v
                  Initial Gating
                          |
                          v
                Unique Security Findings
                          |
                          v
                  Future Security Work
                    /      |       \
                   /       |        \
                  v        v         v
             Suppression Reachability AI/LLM
                                      |
                                      v
                              Evidence Validation
20. Conclusion

Day 7 extends the Day-6 Semgrep integration by introducing stable finding identity, duplicate detection, and initial deterministic gating.

The important architectural change is that Day 7 now consumes the same normalized finding contract established by Day 6 instead of defining a separate finding structure.

This creates a cleaner foundation for future suppression, reachability analysis, evidence validation, and AI-assisted security triage.


---

## One important thing before you run it

Your **current `semgrep_results.sarif` is the differential-scan fixture**, containing the two findings:

```text
Day-05\payment.py:2
Day-05\user.py:2

Your README records exactly those two findings.

Therefore, after replacing test_semgrep_adapter.py, run:

python -m unittest Day-06/test_semgrep_adapter.py -v

You should now get:

Ran 18 tests

OK

Then:

python Day-07\deduplicate.py

and:

python Day-07\gate_findings.py
One architectural note

For Day-7's demonstration, sample_findings.json remains useful because it deliberately contains a duplicate so you can demonstrate deduplication.

For the actual integrated pipeline, the important path is:

Day-06 normalize_findings()
              ↓
       normalized findings
              ↓
Day-07 deduplicate_findings()
              ↓
       unique findings
              ↓
Day-07 determine_gate_decision()

That is the correction OpenCode was pointing toward. Your Day-6 documentation already describes fingerprinting as the foundation for downstream deduplication and gating.
