# Day 6 – Semgrep Integration, SARIF Normalization & Differential Security Scanning

## Objective

The objective of Day 6 was to integrate **Semgrep** into the Agentic VAPT pipeline and understand how scanner findings can be converted into a standardized format for further security analysis.

The main focus areas were:

- Semgrep installation and execution
- Custom Semgrep security rules
- Security finding detection
- SARIF 2.1.0 output
- Finding normalization
- Stable finding fingerprints
- Scanner failure handling
- Automated testing
- Integration with Day 5 differential analysis
- Change-scoped security scanning

---

# 1. Day 6 Architecture

The Day 6 workflow connects Git-based change detection with Semgrep security scanning.

```text
Git Repository
      |
      v
Git Diff / Changed Files
      |
      v
Changed Python Files
      |
      v
Semgrep Security Scanner
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
Normalized Security Findings

This creates the foundation for later stages such as:

Finding deduplication
Suppression
Reachability analysis
AI/LLM triage
Evidence validation
Risk scoring
Security gates
2. Semgrep
What is Semgrep?

Semgrep is a lightweight static analysis tool that searches source code for patterns that may indicate bugs, security issues, or coding problems.

Unlike simple text searching, Semgrep understands programming language syntax and allows rules to be written using code patterns.

For this project, Semgrep is used as one of the security scanners in the VAPT pipeline.

3. Semgrep Installation

Semgrep was installed using Python pip.

python -m pip install semgrep

The installed version was verified using:

semgrep --version

Result:

1.176.0
4. Vulnerable Sample Code

A simple Python file was created for testing Semgrep.

File
Day-06/semgrep_demo.py
Code
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return query


def greet_user(name):
    message = "Hello " + name
    return message

The first function constructs an SQL query by concatenating user-controlled input with an SQL string.

This was intentionally created as a test case for the custom Semgrep rule.

5. Custom Semgrep Rule

A custom Semgrep rule was created to identify SQL query string concatenation.

File
Day-06/semgrep_rules/sql-injection.yml
Rule
rules:
  - id: simple-sql-string-concatenation
    languages:
      - python
    message: Possible SQL injection due to SQL query string concatenation
    severity: WARNING
    patterns:
      - pattern: $QUERY = $SQL + $INPUT
      - metavariable-regex:
          metavariable: $SQL
          regex: '(?i).*select.*'

The rule searches for a pattern where:

A variable is assigned a concatenated expression.
The SQL portion contains SELECT.
Another value is concatenated with the SQL string.

This is a detection heuristic and does not by itself prove that the application contains an exploitable SQL injection vulnerability.

6. Running Semgrep

The custom rule was executed using:

semgrep --config=Day-06/semgrep_rules/sql-injection.yml Day-06/semgrep_demo.py

Semgrep detected one possible security finding.

The finding was located at:

Line: 2
Column: 5 - 70
7. SARIF Output

Semgrep was also executed with SARIF output:

semgrep --config=Day-06/semgrep_rules/sql-injection.yml Day-06/semgrep_demo.py --sarif -o Day-06/semgrep_results.sarif

Output file:

Day-06/semgrep_results.sarif

The generated SARIF document uses:

SARIF Version: 2.1.0

SARIF provides a standardized structure for representing static analysis findings.

The important information includes:

Rule ID
Message
Severity
File location
Start line
Start column
End line
End column
Tool information
Finding fingerprints
8. Why SARIF Normalization is Required

Different security scanners produce different output formats.

For example:

Semgrep
    ↓
SARIF

OSV-Scanner
    ↓
Different output

Trivy
    ↓
Different output

Gitleaks
    ↓
Different output

The Agentic VAPT system needs a common finding structure.

Therefore:

Scanner Output
      |
      v
Normalization
      |
      v
Common Finding Format

This allows downstream components to process findings without depending on the original scanner format.

9. Semgrep Adapter
File
Day-06/semgrep_adapter.py

The adapter performs the following operations:

Run Semgrep
     |
     v
Generate SARIF
     |
     v
Load SARIF
     |
     v
Extract Findings
     |
     v
Normalize Fields
     |
     v
Generate Fingerprint
     |
     v
Return Normalized Finding
10. Normalized Finding Format

The adapter converts Semgrep findings into a common structure.

Example:

{
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
}

Example output:

Scanner     : Semgrep
Rule ID     : Day-06.semgrep_rules.simple-sql-string-concatenation
Message     : Possible SQL injection due to SQL query string concatenation
Severity    : warning
File        : Day-05\payment.py
Location    : 2:5 - 2:65
Fingerprint : eef739e884dc2afba0dd2126c18c1751d801379e901d0e2c259ddfefdfa1787d
11. Stable Finding Fingerprint

Security scanners may provide their own fingerprints, but the Agentic VAPT system needs a deterministic finding identity.

The adapter therefore generates a SHA-256 fingerprint.

The fingerprint is generated using:

Rule ID
+
Normalized File Path
+
Start Line
+
End Line

Conceptually:

Fingerprint Input
       |
       v
SHA-256
       |
       v
64-character hexadecimal fingerprint

Example:

eef739e884dc2afba0dd2126c18c1751d801379e901d0e2c259ddfefdfa1787d

The same finding information produces the same fingerprint.

Different finding locations produce different fingerprints.

This provides a foundation for:

Finding deduplication
Finding tracking
Suppression
Historical comparison
Regression detection
12. Scanner Failure Semantics

The scanner adapter does not treat every Semgrep execution as successful.

The following execution states are handled:

SUCCESS
TIMEOUT
EXECUTION_ERROR
INVALID_OUTPUT
FINDINGS
NO_FINDINGS
SUCCESS

Semgrep executed successfully.

FINDINGS

Semgrep executed successfully and security findings were detected.

NO_FINDINGS

Semgrep executed successfully but no findings were produced.

TIMEOUT

Semgrep exceeded the configured execution timeout.

EXECUTION_ERROR

The scanner could not execute correctly.

Examples:

Semgrep executable unavailable
Unexpected process exit code
Runtime failure
INVALID_OUTPUT

The scanner execution may have completed, but the generated output is not valid SARIF 2.1.0.

This distinction is important because scanner failures should not silently appear as "no vulnerabilities found."

13. Differential Security Scanning

Day 5 introduced differential analysis.

The purpose of differential analysis is to identify the parts of the source code affected by recent Git changes.

Day 6 connects that concept with Semgrep.

File
Day-06/differential_semgrep.py

The script obtains changed Python files using:

git diff --name-only HEAD~1 HEAD

Only .py files are selected.

Existing files are then passed to Semgrep.

14. Differential Semgrep Workflow
Latest Git Commit
       |
       v
Git Diff
       |
       v
Changed Files
       |
       v
Filter Python Files
       |
       v
Check Existing Files
       |
       v
Run Semgrep
       |
       v
Generate SARIF
       |
       v
Normalize Findings
       |
       v
Generate Fingerprints

This reduces unnecessary scanning because security analysis can be focused on changed files.

15. Differential Scan Result

The differential scanner identified:

Changed Python Files : 3

- Day-05/differential_analysis.py
- Day-05/payment.py
- Day-05/user.py

Semgrep then scanned only these changed Python files.

The scan produced:

Semgrep Execution : SUCCESS
Scan Status       : FINDINGS
Normalized Findings : 2

Detected possible findings:

Day-05/payment.py
Day-05/user.py

Both findings were normalized and assigned separate fingerprints.

16. Unit Testing
File
Day-06/test_semgrep_adapter.py

The adapter was tested using Python's built-in unittest framework.

Tests cover:

SARIF file existence
SARIF version validation
Finding count
Finding field normalization
Deterministic fingerprints
Fingerprint length
Different finding fingerprints
FINDINGS status
NO_FINDINGS status
INVALID_OUTPUT status
TIMEOUT status
EXECUTION_ERROR status
Successful Semgrep execution
Semgrep finding exit code
Unexpected Semgrep exit code
Missing Semgrep executable
Semgrep timeout

The scanner execution failure tests use mocking so that failure conditions can be tested deterministically without depending on the actual environment.

17. Test Result

The complete adapter test suite passed successfully.

Ran 17 tests in 0.008s

OK

Result:

17 / 17 tests passed
0 failures
0 errors
18. Day 6 File Structure
Day-06/
├── README.md
├── semgrep_demo.py
├── semgrep_results.sarif
├── semgrep_adapter.py
├── differential_semgrep.py
├── test_semgrep_adapter.py
└── semgrep_rules/
    └── sql-injection.yml
19. Day 5 → Day 6 Integration

The previous workflow from Day 5 focused on identifying changed source-code areas.

Day 6 extends that workflow by adding an actual security scanner.

Day 5
Git Diff
   ↓
Changed Files
   ↓
Affected Functions
   ↓
Security-Relevant Scope
Day 6
Git Diff
   ↓
Changed Files
   ↓
Security-Relevant Scope
   ↓
Semgrep
   ↓
SARIF
   ↓
Normalized Findings
   ↓
Stable Fingerprints

This represents the transition from change detection to change-aware security detection.

20. Relevance to Agentic VAPT

This work directly supports the detection and gating layer of the Agentic VAPT architecture.

The scanner pipeline can eventually support multiple scanners:

                 ┌── Semgrep
                 |
Changed Code ────┼── OSV-Scanner
                 |
                 ├── Trivy
                 |
                 ├── Gitleaks
                 |
                 └── Checkov
                         |
                         v
                 SARIF / Normalization
                         |
                         v
                 Finding Fingerprint
                         |
                         v
                 Deduplication
                         |
                         v
                 Suppression / Gating
                         |
                         v
                 Reachability / AI Analysis

Semgrep is therefore the first scanner integration used to establish the adapter and normalization pattern.

21. Key Learnings
1. Semgrep

Learned how Semgrep can perform pattern-based static security analysis.

2. Custom Security Rules

Learned how to create a custom Semgrep YAML rule for detecting a security-relevant code pattern.

3. SARIF

Learned how scanner findings can be represented using SARIF 2.1.0.

4. Finding Normalization

Learned why different scanner outputs need to be converted into a common internal representation.

5. Fingerprinting

Implemented deterministic SHA-256 fingerprints for security findings.

6. Failure Handling

Implemented explicit scanner execution states instead of silently treating failures as clean scans.

7. Automated Testing

Created unit tests covering normal behavior and scanner failure scenarios.

8. Differential Scanning

Connected Git change detection with Semgrep so that security analysis can focus on changed files.

22. Day 6 Status

Status: Completed

Completed Work
 Installed Semgrep
 Verified Semgrep installation
 Created vulnerable Python sample
 Created custom Semgrep rule
 Executed Semgrep
 Generated SARIF 2.1.0
 Created Semgrep adapter
 Normalized security findings
 Extracted severity
 Implemented stable finding fingerprints
 Implemented scanner failure semantics
 Created automated tests
 Passed 17/17 tests
 Connected Git differential analysis with Semgrep
 Performed change-scoped security scanning
 Generated normalized findings from changed files
23. Commands Used
Check Semgrep
semgrep --version
Run Semgrep
semgrep --config=Day-06/semgrep_rules/sql-injection.yml Day-06/semgrep_demo.py
Generate SARIF
semgrep --config=Day-06/semgrep_rules/sql-injection.yml Day-06/semgrep_demo.py --sarif -o Day-06/semgrep_results.sarif
Run Semgrep Adapter
python Day-06/semgrep_adapter.py
Run Differential Semgrep
python Day-06/differential_semgrep.py
Run Tests
python -m unittest Day-06/test_semgrep_adapter.py -v
24. Final Day 6 Pipeline
                    Git Repository
                           |
                           v
                     Git Diff
                           |
                           v
                  Changed Python Files
                           |
                           v
                  Differential Scope
                           |
                           v
                    Semgrep Scanner
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
                Normalized Security Findings
                           |
                           v
                 Future Security Pipeline
                           |
             ┌─────────────┼─────────────┐
             v             v             v
        Deduplication   Suppression   Reachability
                                           |
                                           v
                                      AI / LLM Triage
25. Conclusion

Day 6 established the first practical security scanner integration for the Agentic VAPT learning pipeline.

The implementation now demonstrates how Git-based differential analysis can be connected to Semgrep, how scanner results can be represented using SARIF 2.1.0, and how findings can be normalized and assigned deterministic fingerprints.

The next stages can build on this foundation by adding additional scanners, deduplication, suppression, reachability analysis, confidence scoring, and AI-assisted security triage.
