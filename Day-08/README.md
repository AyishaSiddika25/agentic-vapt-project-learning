# Day 8 – Security Finding Context & Risk-Aware Triage

## Objective

The objective of Day 8 is to learn how security findings can be enriched with additional security context and prioritized before they are passed to deeper security analysis or validation stages.

In Day 6, security findings were normalized from Semgrep SARIF output.

In Day 7, findings were given stable fingerprints, duplicates were removed, and an initial severity-based gate was applied.

Day 8 extends this process by introducing:

- Finding context enrichment
- Security-related context indicators
- Risk scoring
- Finding prioritization
- Risk-aware triage

The goal is to understand how contextual information can help prioritize security findings.

This implementation is a learning/demo implementation and does not prove exploitability.

---

# 1. Day 6 → Day 7 → Day 8

The learning pipeline developed so far is:

```text
Git Changes
     |
     v
Changed Files
     |
     v
Semgrep Security Scan
     |
     v
SARIF Output
     |
     v
Finding Normalization
     |
     v
Stable Fingerprint
     |
     v
Deduplication
     |
     v
Initial Gate
     |
     v
Context Enrichment
     |
     v
Risk Scoring
     |
     v
Triage / Prioritization

Each day introduced a different part of the security-analysis pipeline.

2. Day 6 – Semgrep Integration

Day 6 focused on integrating Semgrep into the learning pipeline.

Main topics:

Semgrep scanning
Custom Semgrep rules
SARIF 2.1.0
Finding normalization
Stable fingerprints
Differential security scanning
Scanner execution states

The normalized finding structure established in Day 6 contains:

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

This normalized structure becomes the input for later stages.

3. Day 7 – Fingerprinting, Deduplication & Gating

Day 7 focused on processing normalized security findings.

The main steps were:

Normalized Findings
        |
        v
Fingerprinting
        |
        v
Deduplication
        |
        v
Initial Severity Gate

The Day 7 implementation:

Creates deterministic finding fingerprints.
Removes duplicate findings.
Keeps the first occurrence of a duplicate.
Applies an initial severity-based gate.

The Day 7 sample demonstrated:

Total findings: 3
Unique findings: 2
Duplicates: 1

After gating:

High   -> KEEP
Medium -> KEEP
Other  -> FILTER

Day 8 starts from the concept of unique/gated findings and adds additional context and prioritization.

4. Why Finding Context Matters

A scanner finding contains useful information, but scanner severity alone may not provide enough context for prioritization.

For example:

query = "SELECT * FROM users WHERE id=" + user_id

A scanner may report a possible SQL injection.

However, additional questions can help determine its importance:

Is user-controlled input involved?
Is database-related code involved?
Is authentication involved?
Is command execution involved?
Is sensitive data involved?
Is the code associated with an external endpoint?

These contextual signals can help prioritize findings for deeper analysis.

5. Finding Context

Finding context refers to additional information associated with a security finding that may help determine its priority.

The Day 8 implementation checks for several security-related indicators:

Finding
   |
   +-- User Input
   |
   +-- Database Operation
   |
   +-- Authentication
   |
   +-- Command Execution
   |
   +-- External Endpoint
   |
   +-- Sensitive Data

These indicators are represented as Boolean values:

True
False

For example:

database_operation: True
authentication: False
command_execution: False
6. Context Enrichment

The file:

Day-08/context_enrichment.py

is responsible for adding contextual indicators to security findings.

It loads the findings from:

Day-08/sample_findings.json

and checks the finding's:

Rule ID
Message
File path

for security-related keywords.

The implementation identifies these context categories:

user_input
database_operation
authentication
command_execution
external_endpoint
sensitive_data

The result is added to the finding as a context object.

Example:

"context": {
    "user_input": false,
    "database_operation": true,
    "authentication": true,
    "command_execution": false,
    "external_endpoint": false,
    "sensitive_data": false
}
7. Security Context Indicators
7.1 User Input

The implementation checks for indicators such as:

input
request
parameter
user

These can indicate that a finding may be associated with user-controlled data.

Example:

username = request.args.get("username")
7.2 Database Operation

The implementation checks for indicators such as:

sql
query
database
execute

These can indicate database-related operations.

Example:

query = "SELECT * FROM users WHERE id=" + user_id
7.3 Authentication

The implementation checks for indicators such as:

login
password
authentication
token
session

These can indicate authentication or credential-related code.

Example:

def login(username, password):
    ...
7.4 Command Execution

The implementation checks for indicators such as:

command
shell
subprocess
os.system
exec

These can indicate command or process execution.

Example:

os.system(command)
7.5 External Endpoint

The implementation checks for indicators such as:

api
endpoint
request

These can indicate code associated with external application interfaces.

7.6 Sensitive Data

The implementation checks for indicators such as:

password
secret
credential
token

These can indicate sensitive information.

8. Context Enrichment Example

For the SQL injection finding:

python.sql-injection

the current implementation detected:

user_input: False
database_operation: True
authentication: True
command_execution: False
external_endpoint: False
sensitive_data: False

For the hardcoded password finding:

python.hardcoded-password

the implementation detected:

user_input: False
database_operation: False
authentication: True
command_execution: False
external_endpoint: False
sensitive_data: True

For the command injection finding:

python.command-injection

the implementation detected:

user_input: False
database_operation: False
authentication: False
command_execution: True
external_endpoint: False
sensitive_data: False
9. Risk Scoring

After context enrichment, the finding can be assigned a simple risk score.

The file:

Day-08/risk_scoring.py

contains the scoring logic.

The current learning model uses:

Severity
High   = +3
Medium = +2
Low    = +1
Context indicators
User input          = +2
Database operation  = +2
Authentication      = +2
Command execution   = +3
External endpoint   = +2
Sensitive data      = +2

The score is calculated by adding the applicable points.

10. Risk Score Example

Consider the SQL injection finding.

Its severity is:

High

Therefore:

High severity = +3

The finding also has:

Database operation = +2
Authentication     = +2

Therefore:

3 + 2 + 2 = 7

Final risk score:

7
11. Priority Classification

The current implementation converts the risk score into a priority category.

The rules are:

Score 8 or above
    HIGH

Score 5–7
    MEDIUM

Score 0–4
    LOW

Therefore:

Risk Score 7
     |
     v
MEDIUM

This is a simple learning model and is not intended to represent a production security-risk standard.

12. Risk-Aware Triage

The file:

Day-08/triage.py

connects the context-enrichment and risk-scoring stages.

The process is:

Security Finding
       |
       v
Context Enrichment
       |
       v
Calculate Risk Score
       |
       v
Determine Priority
       |
       v
Triage Result

Each finding receives:

context
risk_score
priority
13. Day 8 Implementation Flow

The complete Day 8 implementation is:

sample_findings.json
        |
        v
context_enrichment.py
        |
        v
Security Context
        |
        v
risk_scoring.py
        |
        v
Risk Score
        |
        v
Priority
        |
        v
triage.py
        |
        v
Triage Result
14. Project File Structure

The Day 8 directory contains:

Day-08/
├── README.md
├── context_enrichment.py
├── risk_scoring.py
├── triage.py
└── sample_findings.json
README.md

Documents the concepts and implementation learned on Day 8.

sample_findings.json

Contains sample normalized security findings used as input.

context_enrichment.py

Adds security-related context indicators to findings.

risk_scoring.py

Calculates a simple risk score and determines priority.

triage.py

Connects the enrichment and scoring stages into a simple triage workflow.

15. Sample Input

The sample input contains three findings:

1. SQL Injection
2. Hardcoded Password
3. Command Injection

Example:

{
    "scanner": "Semgrep",
    "rule_id": "python.sql-injection",
    "message": "Possible SQL injection",
    "severity": "high",
    "file": "login.py",
    "start_line": 10,
    "start_column": 5,
    "end_line": 10,
    "end_column": 30,
    "fingerprint": "623c073175c1ff7ebea25c6a1f3b495f1c4991a8047046161289ce5ea0d70987"
}

The same normalized finding structure from the previous stages is used.

16. Running Context Enrichment

From the repository root, run:

python Day-08/context_enrichment.py

Expected output:

Finding Context Enrichment:

python.sql-injection | login.py:10
Context:
  user_input: False
  database_operation: True
  authentication: True
  command_execution: False
  external_endpoint: False
  sensitive_data: False

python.hardcoded-password | config.py:5
Context:
  user_input: False
  database_operation: False
  authentication: True
  command_execution: False
  external_endpoint: False
  sensitive_data: True

python.command-injection | admin.py:20
Context:
  user_input: False
  database_operation: False
  authentication: False
  command_execution: True
  external_endpoint: False
  sensitive_data: False
17. Running Risk-Aware Triage

Run:

python Day-08/triage.py

Expected output:

Day 8 – Risk-Aware Finding Triage

python.sql-injection | login.py:10
Severity: high
Risk Score: 7
Priority: MEDIUM
Context:
  - database_operation
  - authentication
--------------------------------------------------
python.hardcoded-password | config.py:5
Severity: medium
Risk Score: 6
Priority: MEDIUM
Context:
  - authentication
  - sensitive_data
--------------------------------------------------
python.command-injection | admin.py:20
Severity: high
Risk Score: 6
Priority: MEDIUM
Context:
  - command_execution
--------------------------------------------------
18. Syntax Validation

All Day 8 Python files were syntax-checked using:

python -m py_compile Day-08/context_enrichment.py Day-08/risk_scoring.py Day-08/triage.py

The command completed successfully without errors.

This confirms that the Day 8 Python implementation is syntactically valid.

19. Actual Day 8 Results

The current implementation produced the following results:

Finding	Severity	Risk Score	Priority
SQL Injection	High	7	MEDIUM
Hardcoded Password	Medium	6	MEDIUM
Command Injection	High	6	MEDIUM

Context detected:

Finding	Detected Context
SQL Injection	Database Operation, Authentication
Hardcoded Password	Authentication, Sensitive Data
Command Injection	Command Execution
20. Detection vs Validation

An important concept learned during Day 8 is that a scanner finding is not automatically a confirmed vulnerability.

For example:

Possible SQL Injection

does not automatically mean:

Confirmed SQL Injection

The finding may require additional analysis.

Therefore, the pipeline should distinguish between:

Detection

and:

Validation

Conceptually:

Scanner Detection
       |
       v
Finding Normalization
       |
       v
Deduplication
       |
       v
Context Analysis
       |
       v
Risk-Aware Triage
       |
       v
Deeper Analysis
       |
       v
Validation
       |
       v
Final Security Decision
21. Context Is Not Exploitability

The context indicators used in Day 8 are only signals.

For example:

database_operation = True

does not prove SQL injection.

Similarly:

command_execution = True

does not prove command injection.

The indicators only help identify findings that may deserve further investigation.

22. Relation to Agentic VAPT

The eventual Agentic VAPT architecture can use this type of triage before deeper AI analysis or exploit validation.

Conceptually:

Git Changes
     |
     v
Security Scanners
     |
     v
SARIF
     |
     v
Finding Normalization
     |
     v
Fingerprinting
     |
     v
Deduplication
     |
     v
Initial Gate
     |
     v
Context Enrichment
     |
     v
Risk-Aware Triage
     |
     v
AI Analysis
     |
     v
Exploit Validation
     |
     v
Final Decision

This provides a structured path from raw scanner output toward deeper security reasoning.

23. Why Triage Is Useful

Security scanners can generate a large number of findings.

Sending every finding directly to an expensive analysis or validation stage may increase:

Processing time
Computational requirements
API usage
Analysis noise
False-positive workload

A triage stage can help prioritize findings.

Conceptually:

Many Scanner Findings
        |
        v
Deduplication
        |
        v
Context Enrichment
        |
        v
Risk Scoring
        |
        v
Priority
        |
        v
Deeper Analysis

The exact production architecture may use more advanced signals and policies.

24. Limitations of the Day 8 Implementation

The current implementation is intentionally simple.

It uses keyword-based context detection.

For example:

"sql"
"query"
"password"
"request"
"command"

may trigger a context indicator.

This approach has limitations.

It does not perform:

Data-flow analysis
Call-graph analysis
Control-flow analysis
Taint tracking
Reachability analysis
Exploit verification
LLM reasoning
Runtime validation

Therefore, a context indicator should not be interpreted as proof of vulnerability.

25. Future Improvements

Later stages of the Agentic VAPT project can improve this approach using:

AST information
Tree-sitter
Data-flow analysis
Call graphs
Code property graphs
Entry-point analysis
Repository metadata
Scanner confidence
Historical findings
AI-based triage
Exploit validation

These are future extensions and are not implemented as part of this Day 8 learning exercise.

26. Day 8 Learning Outcome

By completing Day 8, I learned:

Why scanner severity alone may not be sufficient.
What finding context means.
How security-related context indicators can be extracted.
How contextual signals can contribute to risk scoring.
How findings can be assigned a priority.
How risk-aware triage fits into a security-testing pipeline.
Why detection and validation must remain separate.
Why contextual signals do not automatically prove exploitability.
27. Day 8 Status

Status: Completed

Completed Work
Finding context enrichment
Security context indicators
Risk scoring
Priority classification
Risk-aware triage
Sample finding processing
Python syntax validation
Validation
Context enrichment       PASS
Risk scoring             PASS
Priority classification  PASS
Triage workflow          PASS
Syntax validation        PASS
28. Final Day 8 Flow

The complete learning flow is:

Day 6
Semgrep
   |
   v
SARIF
   |
   v
Normalized Findings
        |
        v
Day 7
Fingerprinting
        |
        v
Deduplication
        |
        v
Initial Gate
        |
        v
Day 8
Context Enrichment
        |
        v
Risk Indicators
        |
        v
Risk Score
        |
        v
Priority
        |
        v
Triage
        |
        v
Future:
AI Analysis & Exploit Validation
29. Summary

Day 8 extended the previous security-finding pipeline by introducing contextual analysis and risk-aware triage.

The implementation takes normalized findings and enriches them with security-related context indicators.

These indicators are then combined with scanner severity to calculate a simple risk score.

The risk score is converted into a priority category:

HIGH
MEDIUM
LOW

The final Day 8 pipeline is:

Finding
   |
   v
Context Enrichment
   |
   v
Risk Indicators
   |
   v
Risk Score
   |
   v
Priority
   |
   v
Triage Result

This provides a foundation for later stages where prioritized findings can be passed to deeper AI analysis and security validation.
