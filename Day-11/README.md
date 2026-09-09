# Day 11 – LLM-Based Security Analysis

## Objective

The objective of Day 11 is to understand how security findings can be prepared for analysis by a Large Language Model (LLM) and how the expected security reasoning can be represented as a structured result.

Day 10 introduced relevant source-code context.

Day 11 builds on that by combining:

- Security finding metadata
- Risk information
- Security context
- Relevant source-code evidence
- Structured LLM request preparation
- Structured security-analysis results

The current implementation demonstrates the LLM analysis workflow locally. It does not make an external LLM API call.

---

## Day 11 Learning

The main concepts studied on Day 11 are:

1. LLM client request preparation
2. Structured security-analysis input
3. Combining scanner findings with source-code evidence
4. Security reasoning
5. Evidence-based analysis
6. Confidence estimation
7. Recommended next steps
8. Structured AI analysis results
9. Separation between scanner evidence and AI reasoning
10. Preparing results for later security validation

---

## Day 10 → Day 11

### Day 10

Day 10 focused on extracting relevant source-code context around a security finding.

The flow was:

```text
Security Finding
       +
Security Context
       +
Relevant Source Code
       ↓
AI-Ready Security Prompt
Day 11

Day 11 builds on this by preparing a structured request and producing a structured security-analysis result.

Security Finding
       +
Risk Information
       +
Security Context
       +
Source-Code Evidence
       ↓
Structured LLM Request
       ↓
Security Analysis
       ↓
Structured Result
       ↓
results.json
Folder Structure
Day-11/
├── README.md
├── sample_findings.json
├── llm_client.py
├── security_analysis.py
└── results.json
File Description
File	Purpose
README.md	Day 11 documentation
sample_findings.json	Sample security findings with context and source-code evidence
llm_client.py	Prepares structured information for an LLM request
security_analysis.py	Performs the local security-analysis simulation and generates results
results.json	Generated structured security-analysis results
1. Sample Security Findings

The sample_findings.json file contains two sample security findings.

Finding 1 – SQL Injection
Rule ID:
python.sql-injection

Severity:
high

File:
Day-10/login.py

Risk Score:
7

Priority:
MEDIUM

Security context includes:

User Input: True
Database Operation: True
Authentication: True

Relevant source code:

query = "SELECT * FROM users WHERE username='" + username + "'"
return query
Finding 2 – Hardcoded Password
Rule ID:
python.hardcoded-password

Severity:
medium

File:
Day-10/config.py

Risk Score:
6

Priority:
MEDIUM

Security context includes:

Authentication: True
Sensitive Data: True

Relevant source code:

def get_database_config():
    username = "admin"
    password = "Admin@12345"

    return username, password
2. LLM Client Request Preparation

The llm_client.py script prepares the information that would be provided to an LLM.

The request contains:

System Message
Finding Metadata
Risk Information
Security Context
Source Code
Expected Output Structure

The request is represented as a Python dictionary.

Example structure:

{
    "system_message": "...",
    "finding": {
        "scanner": "Semgrep",
        "rule_id": "python.sql-injection",
        "message": "Possible SQL injection",
        "severity": "high",
        "file": "Day-10/login.py"
    },
    "risk": {
        "risk_score": 7,
        "priority": "MEDIUM"
    },
    "security_context": {},
    "source_code": "...",
    "requested_output": [
        "security_reasoning",
        "evidence",
        "confidence",
        "recommended_next_step"
    ]
}

This demonstrates how structured security information can be passed to an LLM rather than sending only a scanner message.

3. Source-Code Evidence

The LLM request includes the source-code context collected during Day 10.

For example:

2: query = "SELECT * FROM users WHERE username='" + username + "'"
3: return query

This gives the analysis process actual code evidence associated with the security finding.

The purpose is to improve security reasoning by providing relevant evidence instead of relying only on the scanner's message.

4. Structured Security Analysis

The security_analysis.py script processes each finding and creates a structured analysis result.

The analysis contains four main sections:

1. Security Reasoning
2. Evidence
3. Confidence
4. Recommended Next Step
Security Reasoning

Explains why the finding appears security-relevant based on the available evidence.

Example:

The finding appears security-relevant based on the scanner
result, security context, and available source-code evidence.
Evidence

The analysis records contextual evidence such as:

User-controlled input is involved.
A database operation is involved.
The finding is related to authentication.
Relevant source-code evidence is available.
Confidence

A confidence level is assigned based on the sample finding severity:

High
Medium
Low
Recommended Next Step

The analysis recommends further validation:

Validate the suspected security path using source-code
analysis and security testing before treating the finding
as confirmed.
5. Separation of Evidence and AI Reasoning

An important concept learned on Day 11 is that scanner evidence and AI reasoning should remain distinguishable.

The scanner provides:

Finding
Rule ID
Severity
File
Location

Additional analysis provides:

Security Context
Risk Score
Source-Code Evidence

The AI analysis provides:

Security Reasoning
Evidence Interpretation
Confidence
Recommended Next Step

Therefore:

Scanner Evidence
       +
Source-Code Evidence
       +
Security Context
       ↓
AI Security Reasoning

The AI result should not automatically be treated as proof that a vulnerability is exploitable.

6. Generated Results

Running:

python Day-11/security_analysis.py

generates:

Day-11/results.json

The generated result contains the original finding and its corresponding analysis.

Example structure:

{
    "finding": {
        "scanner": "Semgrep",
        "rule_id": "python.sql-injection",
        "severity": "high"
    },
    "llm_analysis": {
        "finding": "Possible SQL injection",
        "security_reasoning": "...",
        "evidence": [
            "User-controlled input is involved.",
            "A database operation is involved."
        ],
        "confidence": "High",
        "recommended_next_step": "..."
    }
}
7. Validation

The Python files were syntax-checked using:

python -m py_compile Day-11/llm_client.py
python -m py_compile Day-11/security_analysis.py

The request preparation was tested using:

python Day-11/llm_client.py

The complete security-analysis workflow was tested using:

python Day-11/security_analysis.py

The generated JSON was validated using:

python -m json.tool Day-11/results.json

The JSON validation completed successfully.

8. Actual Day 11 Output

The SQL injection finding produced:

Finding: Possible SQL injection

Confidence: High

Evidence included:

User-controlled input is involved.
A database operation is involved.
The finding is related to authentication.
Relevant source-code evidence is available.

The hardcoded-password finding produced:

Finding: Possible hardcoded password

Confidence: Medium

Evidence included:

The finding is related to authentication.
Sensitive data may be involved.
Relevant source-code evidence is available.
9. Important Limitation

The current Day 11 implementation does not make a real external LLM API call.

Instead, it demonstrates the structure of:

LLM Request
       ↓
Security Analysis
       ↓
Structured Result

The security_analysis.py implementation simulates the type of structured response that an LLM could produce.

This approach allows the security-analysis data flow and output contract to be understood before connecting a real model.

A future implementation can replace the simulated analysis with an actual LLM client while preserving the structured input/output design.

10. Agentic VAPT Relevance

Day 11 represents the transition from traditional scanner output toward AI-assisted security reasoning.

The broader Agentic VAPT pipeline can be represented as:

Git Repository
      ↓
Git Diff
      ↓
Changed Files
      ↓
Semgrep / Security Scanners
      ↓
SARIF Findings
      ↓
Normalization
      ↓
Fingerprinting
      ↓
Deduplication
      ↓
Gating
      ↓
Risk Context
      ↓
Risk Scoring
      ↓
Source-Code Context
      ↓
LLM Security Analysis
      ↓
Security Reasoning
      ↓
Validation
      ↓
Final Security Decision

Day 11 focuses specifically on:

Source-Code Context
        ↓
LLM Security Analysis
        ↓
Structured Security Result
11. Key Concepts Learned
LLM Client

A component responsible for preparing information and communicating with an LLM.

Structured Prompt / Request

A request containing clearly separated security information such as finding metadata, context, risk, and source code.

Security Reasoning

The process of interpreting a scanner finding using available security evidence.

Evidence

Information supporting the security analysis.

Confidence

An indication of how strongly the available evidence supports the analysis.

Security Validation

A later step used to determine whether a suspected vulnerability is actually reachable or exploitable.

AI-Assisted Security Analysis

Using an LLM to help interpret and prioritize security findings while keeping validation separate.

12. Day 11 Status
Day 11 – LLM-Based Security Analysis

Status: COMPLETED ✅

Completed activities:

✓ Created structured security findings
✓ Included source-code evidence
✓ Prepared structured LLM requests
✓ Added risk information
✓ Added security context
✓ Implemented structured security reasoning
✓ Added evidence extraction
✓ Added confidence
✓ Added recommended next steps
✓ Generated results.json
✓ Validated generated JSON
Final Day 11 Flow
Semgrep Finding
      ↓
Finding Metadata
      ↓
Risk Score + Priority
      ↓
Security Context
      ↓
Relevant Source Code
      ↓
Structured LLM Request
      ↓
Security Analysis
      ↓
Reasoning + Evidence
      ↓
Confidence
      ↓
Recommended Next Step
      ↓
results.json

Day 11 successfully demonstrates the LLM security-analysis stage of the Agentic VAPT learning pipeline.
