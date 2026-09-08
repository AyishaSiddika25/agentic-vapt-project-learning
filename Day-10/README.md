# Day 10 – Source-Code Context for AI Security Analysis

## Objective

The objective of Day 10 is to improve the security-analysis pipeline by providing the AI with relevant source-code context along with the security finding and security metadata.

In Day 9, the analysis prompt used finding information such as:

- Security finding
- Rule ID
- Scanner
- Severity
- Risk score
- Priority
- Security context

However, the prompt did not contain the actual source code where the finding occurred.

Day 10 addresses this limitation by extracting the relevant source-code lines around the finding and including them in the AI-ready security-analysis prompt.

---

## Day 10 Learning

Today I learned how to:

- Extract source code around a security finding
- Use finding line numbers to identify relevant source-code locations
- Include surrounding lines as context
- Build a context-aware security-analysis prompt
- Combine finding metadata, security context, and source code
- Prepare an AI-ready input for security reasoning

---

## Why Source-Code Context Is Important

A security scanner may report:

```text
Possible SQL injection

However, the finding message alone does not provide enough information to understand the actual code.

For example:

query = "SELECT * FROM users WHERE username='" + username + "'"

Providing this source code to the AI gives it concrete evidence that can be used during security analysis.

Therefore:

Finding Metadata
       +
Security Context
       +
Relevant Source Code
       ↓
   AI-Ready Prompt
       ↓
 Security Analysis
1. Day 10 Folder Structure
Day-10/
│
├── README.md
├── sample_findings.json
├── login.py
├── config.py
├── source_context.py
├── llm_prompt.py
└── security_context_analysis.py
2. Sample Security Findings

The file:

sample_findings.json

contains sample security findings from Semgrep.

The findings include:

SQL injection
Hardcoded password

Each finding contains information such as:

scanner
rule_id
message
severity
file
start_line
end_line
risk_score
priority
context

Example:

{
    "rule_id": "python.sql-injection",
    "message": "Possible SQL injection",
    "severity": "high",
    "file": "Day-10/login.py",
    "start_line": 4,
    "end_line": 4
}
3. Sample Source Code
login.py

The SQL injection example contains:

def login(username):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    return query

The finding points to line 4.

config.py

The hardcoded-password example contains:

def get_database_config():
    username = "admin"
    password = "Admin@12345"

    return username, password

The finding points to line 3.

4. Source-Code Context Extraction

File:

source_context.py

This script extracts source-code lines around the finding location.

The function:

extract_source_context(
    file_path,
    start_line,
    end_line,
    context_lines=2
)

uses the finding location and includes two lines before and after the finding when available.

Example

For:

Day-10/login.py:4

the extracted context was:

2: query = "SELECT * FROM users WHERE username='" + username + "'"
3: return query

For:

Day-10/config.py:3

the extracted context was:

1: def get_database_config():
2: username = "admin"
3: password = "Admin@12345"
4:
5: return username, password

This provides the AI with the code surrounding the reported finding.

5. LLM Prompt Construction

File:

llm_prompt.py

This script builds a structured security-analysis prompt.

The prompt combines:

Finding
Rule ID
Scanner
Severity
File
Location
Risk Score
Priority
Security Context
Relevant Source Code

The prompt requests the analysis in four sections:

1. Security Reasoning
2. Evidence
3. Confidence
4. Recommended Next Step

The prompt also instructs the AI to use the source code as evidence and avoid claiming that a vulnerability is confirmed without sufficient evidence.

6. End-to-End Integration

File:

security_context_analysis.py

This script connects the source-context extraction and prompt-generation components.

The workflow is:

sample_findings.json
        |
        v
 Load Security Findings
        |
        v
 Extract Finding Location
        |
        v
 Extract Relevant Source Code
        |
        v
 Build AI Security Prompt
        |
        v
 Display AI-Ready Prompt
7. End-to-End Architecture
                Security Finding
                       |
                       v
              Finding Metadata
                       |
                       +
                       |
              Security Context
                       |
                       +
                       |
             Source-Code Location
                       |
                       v
             Source Context
              Extraction
                       |
                       v
              Relevant Code
                       |
                       v
             LLM Prompt Builder
                       |
                       v
             AI-Ready Security
                  Analysis
8. Validation

The following commands were used to validate the Day 10 implementation.

Validate source files
python -m py_compile Day-10/login.py Day-10/config.py

Result:

No syntax errors
Validate source-context extraction
python -m py_compile Day-10/source_context.py

Then:

python Day-10/source_context.py

The script successfully extracted the relevant source-code context for both findings.

Validate LLM prompt generation
python -m py_compile Day-10/llm_prompt.py

Then:

python Day-10/llm_prompt.py

The generated prompt successfully contained:

Finding
Rule ID
Scanner
Severity
Security Context
Relevant Source Code
Validate End-to-End Integration
python -m py_compile Day-10/security_context_analysis.py

Then:

python Day-10/security_context_analysis.py

The script successfully processed both findings and generated AI-ready security-analysis prompts containing the relevant source code.

9. Example Output

For the SQL injection finding:

Finding: python.sql-injection | Day-10/login.py:4

The prompt contained:

Relevant Source Code:

2: query = "SELECT * FROM users WHERE username='" + username + "'"
3: return query

For the hardcoded-password finding:

Finding: python.hardcoded-password | Day-10/config.py:3

The prompt contained:

Relevant Source Code:

1: def get_database_config():
2: username = "admin"
3: password = "Admin@12345"
4:
5: return username, password
10. Day 9 → Day 10 Improvement
Day 9

The AI prompt mainly contained:

Finding
+
Security Metadata
+
Security Context

The AI did not receive the actual source code.

Day 10

The prompt now contains:

Finding
+
Security Metadata
+
Security Context
+
Relevant Source Code

This provides additional evidence for security reasoning.

11. Agentic VAPT Relevance

Source-code context is important for an Agentic VAPT system because scanner findings alone may not provide enough information for intelligent security analysis.

A future security-analysis stage can use:

Scanner Finding
       ↓
Finding Fingerprint
       ↓
Risk Context
       ↓
Relevant Source Code
       ↓
AI Security Reasoning
       ↓
Validation
       ↓
Final Security Decision

Day 10 focuses specifically on preparing the relevant source-code context for the AI analysis stage.

12. Important Limitation

The Day 10 implementation prepares an AI-ready prompt.

It does not make an actual LLM API call.

The current flow is:

Finding
   ↓
Source Context
   ↓
Prompt
   ↓
AI-Ready Input

Actual model invocation can be integrated in a later stage.

13. Key Concepts Learned
Source-code context extraction
Line-based source scoping
Finding location
Context lines
Evidence-based AI analysis
Context-aware prompting
Security finding enrichment
AI-ready security analysis
Separation of detection and reasoning
14. Day 10 Status

Status: Successfully Completed ✅

Completed
 Created sample security findings
 Created vulnerable sample source files
 Implemented source-code context extraction
 Tested source-code extraction
 Implemented context-aware LLM prompt generation
 Tested prompt generation
 Integrated source extraction with prompt generation
 Tested end-to-end workflow
 Validated Python syntax
15. Final Day 10 Flow
Semgrep Finding
      |
      v
Finding Metadata
      |
      v
Security Context
      |
      v
Finding Location
      |
      v
Source-Code Extraction
      |
      v
Relevant Source Context
      |
      v
Context-Aware LLM Prompt
      |
      v
AI-Ready Security Analysis

Day 10 – Source-Code Context for AI Security Analysis: SUCCESSFULLY COMPLETED ✅
