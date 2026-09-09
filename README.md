# 🛡️ AI-Powered Agentic VAPT

### Automated • AI-Assisted • Exploit-Verified Security Testing

> **A learning and implementation repository for understanding and building an AI-powered Agentic VAPT pipeline that combines code intelligence, security scanners, AI reasoning, vulnerability validation, risk analysis, and CI/CD automation.**

---

## 📌 About This Repository

This repository documents my **daily learning, research, experiments, implementation work, and technical understanding** related to the **AI-Powered Agentic VAPT Project**.

The goal is to understand how traditional Vulnerability Assessment and Penetration Testing (VAPT) techniques can be enhanced using:

- 🔍 Static Application Security Testing (SAST)
- 🌐 Dynamic Application Security Testing (DAST)
- 🌳 Source-code parsing and AST analysis
- 🧠 Code Property Graphs (CPG)
- 🔄 Differential security analysis
- 🤖 Large Language Models (LLMs)
- 🧩 AI-agent based orchestration
- 🔎 Finding validation
- 🛡️ Exploit verification
- 📊 Risk scoring
- 🕸️ Attack-path analysis
- 🔁 CI/CD integration
- 📋 Security reporting

The repository is primarily a **learning and prototype environment**.  
The daily implementations demonstrate individual concepts that contribute to the larger Agentic VAPT architecture.

---

# 🎯 Project Vision

Traditional security scanners can generate large numbers of findings, but a scanner finding does not automatically mean that a vulnerability is:

- exploitable,
- reachable,
- security-critical,
- relevant to the application's attack surface, or
- worth prioritizing immediately.

The vision of Agentic VAPT is to build a system that can move beyond simple:

```text
SCAN → REPORT

towards:

SCAN
  ↓
UNDERSTAND
  ↓
CORRELATE
  ↓
REASON
  ↓
VALIDATE
  ↓
VERIFY
  ↓
PRIORITIZE
  ↓
REPORT

The system combines deterministic security tooling with AI-assisted reasoning and validation.

🧠 What Is Agentic VAPT?

Agentic VAPT refers to a security-testing architecture in which software agents coordinate multiple security-analysis stages to investigate potential vulnerabilities.

Instead of relying on a single scanner, the system can combine information from:

Source Code
     +
Git History
     +
Static Analysis
     +
Dependency Analysis
     +
Secrets Detection
     +
Infrastructure Scanning
     +
DAST
     +
Code Graphs
     +
LLM Reasoning
     +
Security Validation

The resulting information can be correlated to determine whether a finding represents a meaningful security risk.

🏗️ High-Level Architecture
                    ┌──────────────────────┐
                    │   Git Repository     │
                    │   / Target App       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Git Diff / Change   │
                    │       Analysis        │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Code Intelligence   │
                    │ AST / Tree-sitter /   │
                    │ CPG / Call Graph      │
                    └──────────┬───────────┘
                               │
                               ▼
              ┌──────────────────────────────────┐
              │        Security Scanners         │
              │                                  │
              │  Semgrep                         │
              │  OSV-Scanner                     │
              │  Trivy                           │
              │  Gitleaks                        │
              │  Checkov                         │
              │  DAST                            │
              └────────────────┬─────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   SARIF / Finding     │
                    │    Normalization      │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Fingerprinting &      │
                    │ Deduplication         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Finding Gating &      │
                    │ Filtering             │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Context Enrichment &  │
                    │ Risk Scoring          │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Source-Code Context   │
                    │ Extraction            │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   LLM / AI Security  │
                    │      Analysis         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Vulnerability         │
                    │ Validation            │
                    │ / Exploit Verification│
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Risk & Attack-Path    │
                    │ Analysis              │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Final Security        │
                    │ Decision              │
                    └──────────┬───────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
       ┌────────────────┐             ┌────────────────┐
       │ CI/CD Pipeline │             │ Reports /      │
       │ & Security Gate│             │ Dashboard      │
       └────────────────┘             └────────────────┘
🔬 Core Project Components
1. Git & Change Intelligence

The pipeline begins by understanding what changed in the application.

Instead of scanning everything blindly, Git history and diffs can be used to identify:

Changed files
Changed lines
Changed functions
Potentially affected components
Security-relevant changes
Dependent code

This enables differential security analysis.

Git Commit
    ↓
Git Diff
    ↓
Changed Files
    ↓
Changed Functions
    ↓
Security Analysis Scope
🌳 2. Source-Code Intelligence

Understanding source code is an important part of Agentic VAPT.

Technologies and concepts studied include:

Python AST
Tree-sitter
Abstract Syntax Trees
Code Property Graphs
Call graphs
Data-flow relationships
Control-flow relationships
Reachability analysis

The objective is to transform raw source code into a representation that can support deeper security reasoning.

🔍 3. Security Scanning

The architecture can combine multiple security scanners instead of depending on a single tool.

Potential scanner categories include:

Tool	Security Purpose
Semgrep	Static code analysis and security rules
OSV-Scanner	Dependency vulnerability detection
Trivy	Container, dependency and infrastructure scanning
Gitleaks	Secret detection
Checkov	Infrastructure-as-Code security
DAST tools	Runtime/web application testing

Scanner output can be normalized into a common finding format.

📄 4. SARIF & Finding Normalization

Different security tools produce different output formats.

The project therefore studies normalization into a common security-finding structure.

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
    "fingerprint": "..."
}

This allows findings from different scanners to move through the same downstream pipeline.

🧬 5. Finding Fingerprinting

Each security finding requires a stable identity.

The project studies deterministic fingerprints based on information such as:

Rule ID
    +
Normalized File Path
    +
Start Line
    +
End Line

The resulting identity can be hashed using SHA-256.

Finding
   ↓
Normalized Identity
   ↓
SHA-256 Fingerprint

This helps identify the same finding across scans.

♻️ 6. Finding Deduplication

Multiple scanners or repeated scans may report the same underlying issue.

Deduplication helps reduce duplicate findings.

Raw Findings
     ↓
Fingerprint Generation
     ↓
Duplicate Detection
     ↓
Unique Findings

This improves the quality of downstream analysis.

🚦 7. Finding Gating

Not every scanner result should automatically move to expensive AI analysis.

Finding gating can filter or retain findings based on security policies.

Example learning policy:

HIGH       → KEEP
MEDIUM     → KEEP
LOW        → FILTER

In a production implementation, this can evolve into more sophisticated policy-based gating.

📊 8. Context Enrichment & Risk Scoring

A finding becomes more useful when additional security context is available.

The project studies indicators such as:

User Input
Database Operation
Authentication
Command Execution
External Endpoint
Sensitive Data

These signals can contribute to a contextual risk score.

Example:

Scanner Severity
       +
Security Context
       +
Risk Signals
       ↓
Contextual Risk Score
       ↓
Priority

The learning implementation uses a simple scoring model to demonstrate the concept.

🤖 9. LLM-Based Security Analysis

LLMs can be used to assist in interpreting security findings.

Instead of sending only:

"Possible SQL injection"

the AI analysis stage can receive:

Finding Metadata
      +
Risk Score
      +
Security Context
      +
Relevant Source Code

The LLM can then provide structured reasoning such as:

Security Reasoning
Evidence
Confidence
Recommended Next Step
🧠 10. Source-Code-Aware AI Reasoning

A major concept studied in this repository is that AI analysis should be evidence-driven.

The AI should receive relevant source-code context instead of relying only on a scanner's description.

Example:

query = "SELECT * FROM users WHERE username='" + username + "'"
return query

Combined with:

User Input = True
Database Operation = True

the AI has more information for reasoning about the finding.

🛡️ 11. Finding Validation & Exploit Verification

An important distinction in the project is:

Scanner Finding ≠ Confirmed Vulnerability

A scanner may identify a suspicious pattern, but further validation may be required.

The larger architecture therefore includes a validation stage:

Potential Finding
      ↓
AI Analysis
      ↓
Validation Hypothesis
      ↓
Security Testing
      ↓
Evidence
      ↓
Validated / Not Validated

This is important for reducing false positives and preventing unsupported AI conclusions.

🕸️ 12. Risk & Attack-Path Analysis

A vulnerability should not always be evaluated in isolation.

The architecture can correlate:

Entry points
User-controlled input
Vulnerable functions
Data-flow paths
Authentication boundaries
Sensitive resources
External endpoints
Reachability
Exploitability

Conceptually:

Attacker
   ↓
Entry Point
   ↓
User Input
   ↓
Application Logic
   ↓
Vulnerable Function
   ↓
Sensitive Resource

This helps determine whether a finding participates in a meaningful attack path.

🔄 13. CI/CD Integration

The long-term goal is to integrate security analysis into the development workflow.

A conceptual workflow is:

Developer Commit
       ↓
GitHub Workflow
       ↓
Changed-Code Analysis
       ↓
Security Scanners
       ↓
Finding Processing
       ↓
AI Analysis
       ↓
Validation
       ↓
Risk Decision
       ↓
Security Gate
       ↓
Report

This allows security testing to become part of the software development lifecycle rather than a completely separate activity.

📋 14. Reporting

The final stage can generate structured security information for developers and security teams.

Potential reporting information includes:

Finding
Severity
Risk score
Confidence
Evidence
Source location
Validation status
Exploitability
Attack path
Recommended remediation
Security decision

The goal is to transform raw scanner output into actionable security intelligence.

🧩 Agentic VAPT Pipeline

The overall learning architecture can be summarized as:

┌───────────────────────────────────────────┐
│              SOURCE / GIT                │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│        CHANGE & CODE INTELLIGENCE         │
│   Git Diff • AST • Tree-sitter • CPG      │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│            SECURITY DETECTION             │
│ Semgrep • OSV • Trivy • Gitleaks • Checkov│
│                 • DAST                    │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│        FINDING NORMALIZATION              │
│             SARIF → Finding               │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│       IDENTITY & QUALITY CONTROL          │
│ Fingerprinting • Deduplication • Gating   │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│          RISK & CONTEXT ANALYSIS          │
│ Context Enrichment • Risk Scoring         │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│              AI ANALYSIS                  │
│ Source Context • LLM Reasoning            │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│          SECURITY VALIDATION              │
│ Reachability • Testing • Exploit Evidence │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│          RISK / ATTACK PATH               │
│       Analysis & Correlation              │
└─────────────────────┬─────────────────────┘
                      ↓
┌───────────────────────────────────────────┐
│          FINAL SECURITY DECISION          │
└─────────────────────┬─────────────────────┘
                      ↓
             ┌────────┴────────┐
             ↓                 ↓
          CI/CD             Reports
📚 Learning Progress

This repository is organized as a day-by-day learning journey.
🧪 Technologies & Concepts
Programming
Python
JSON
PowerShell
Git / GitHub
Code Intelligence
Python AST
Tree-sitter
Code Property Graphs
Differential analysis
Call graphs
Data-flow analysis
Security Testing
SAST
DAST
Semgrep
OSV-Scanner
Trivy
Gitleaks
Checkov
AI / LLM
LLM-based security reasoning
Structured prompts
Context-aware analysis
Evidence-based reasoning
AI-assisted triage
Security validation
Security Engineering
Finding normalization
SARIF
Fingerprinting
Deduplication
Finding gating
Risk scoring
Attack-path analysis
Exploit verification
CI/CD security gates
🧠 Key Design Principles
1. Scanner Findings Are Not Automatically Truth

A scanner finding represents a potential security issue.

Finding ≠ Confirmed Vulnerability

Further analysis and validation may be required.

2. AI Reasoning Should Be Evidence-Based

LLM analysis should be grounded in:

Finding
+
Source Code
+
Security Context
+
Security Signals

rather than relying solely on the model's general knowledge.

3. Deterministic Components Should Remain Deterministic

Tasks such as:

parsing,
fingerprinting,
deduplication,
normalization,
policy gating,

should preferably use deterministic logic.

AI can then focus on tasks where reasoning and interpretation provide value.

4. Validation Should Be Separate From Reasoning

An AI model can propose that a vulnerability appears likely.

That does not mean it has proven exploitability.

Therefore:

AI Hypothesis
      ↓
Validation
      ↓
Evidence
      ↓
Security Decision
5. Minimize Unnecessary Context

The system should provide the AI with relevant information rather than blindly sending the entire repository.

Changed Code
     ↓
Relevant Functions
     ↓
Relevant Source Context
     ↓
Security Finding
     ↓
LLM

This can improve both efficiency and analysis quality.

🔐 Security Considerations

Because this project deals with source code and security findings, the implementation must consider:

Secret redaction
Sensitive-data handling
Secure API-key management
Least-privilege execution
Sandbox isolation for validation
Safe handling of generated exploits
Audit logging
Reproducibility
Human review for high-impact decisions

Credentials, API keys, production secrets, and sensitive company data should not be committed to this repository.

🚧 Current Implementation Status

The repository currently focuses on learning and prototyping individual pipeline stages.

Completed Learning Stages
Git & Code Intelligence              ✅
Tree-sitter Parsing                  ✅
Git Diff & Change Scoping            ✅
Differential Analysis                ✅
Semgrep & SARIF                      ✅
Finding Fingerprinting               ✅
Finding Deduplication                ✅
Finding Gating                       ✅
Context Enrichment                   ✅
Risk Scoring                         ✅
LLM Prompt Preparation               ✅
Source-Code Context Extraction       ✅
Structured LLM Request Preparation   ✅
Security Analysis Output             ✅
Future / Advanced Stages
Multi-Scanner Orchestration
        ↓
Dependency / Container / IaC Correlation
        ↓
Code Property Graph Integration
        ↓
LLM Agent Orchestration
        ↓
Real LLM API Integration
        ↓
Reachability Analysis
        ↓
Exploit Validation
        ↓
Attack-Path Analysis
        ↓
CI/CD Security Gate
        ↓
Production Reporting
⚠️ Prototype vs Production

This repository intentionally separates learning implementations from the requirements of a production security platform.

Some current implementations use simplified logic to demonstrate concepts such as:

risk scoring,
security context detection,
finding gating,
AI reasoning,
source-code context extraction.

These implementations should not automatically be considered production-ready security controls.

Production hardening would require:

robust schemas,
comprehensive test suites,
secure execution environments,
real vulnerability validation,
proper LLM integration,
secret handling,
error recovery,
observability,
performance controls,
auditability,
policy enforcement.
📈 Learning Roadmap
PHASE 1 — FOUNDATIONS
│
├── Agentic VAPT Architecture
├── Git
├── AST
├── Tree-sitter
└── SARIF
        ↓
PHASE 2 — SECURITY DETECTION
│
├── Semgrep
├── Differential Scanning
├── Finding Normalization
├── Fingerprinting
└── Deduplication
        ↓
PHASE 3 — INTELLIGENT TRIAGE
│
├── Finding Gating
├── Context Enrichment
├── Risk Scoring
└── Source-Code Context
        ↓
PHASE 4 — AI SECURITY REASONING
│
├── LLM Prompting
├── Structured LLM Requests
├── Security Reasoning
└── Evidence-Based Analysis
        ↓
PHASE 5 — VALIDATION
│
├── Reachability
├── Security Testing
├── Exploit Verification
└── False-Positive Reduction
        ↓
PHASE 6 — AGENTIC ORCHESTRATION
│
├── Security Agents
├── Tool Orchestration
├── Attack-Path Analysis
└── Final Security Decisions
        ↓
PHASE 7 — AUTOMATION
│
├── CI/CD
├── Security Gates
├── Reporting
└── Dashboard
🎯 Final Goal

The ultimate goal is to understand and prototype a security system that can move from:

"Something looks suspicious."

to:

"Here is the finding."
        ↓
"Here is the relevant code."
        ↓
"Here is why it may be vulnerable."
        ↓
"Here is the evidence."
        ↓
"Here is the attack path."
        ↓
"Here is whether it can actually be validated."
        ↓
"Here is the final security decision."

This represents the core idea behind an AI-powered, agentic, exploit-verified VAPT workflow.

📌 Repository Purpose

This repository serves as a technical learning record covering the progression from:

Traditional Security Scanning

to

Context-Aware AI-Assisted Security Analysis

and ultimately toward:

Automated Agentic VAPT with Validation and Risk-Based Decision Making.

🚀 Project Status

Learning & Prototype Development — In Progress

Day 01 ───────────────────────────────► Day 11+
   Foundations
       ↓
   Detection
       ↓
   Triage
       ↓
   AI Analysis
       ↓
   Validation
       ↓
   Agentic VAPT
🛡️ Agentic VAPT

Detect → Understand → Reason → Validate → Verify → Prioritize → Report
