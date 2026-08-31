# Day 02 – Technologies, Concepts & Coding Practice

## Objective

The objective of Day 2 was to study the major technologies and components proposed for the AI-Powered Agentic VAPT system and understand how they fit into the overall architecture.

Along with theoretical learning, small coding exercises were performed to understand Git-based change tracking, source-code structure using AST, and structured vulnerability data.

---

# 1. Git Integration

Git was studied as the source-code and change-tracking mechanism for the project.

## Key Concepts Learned

- Git repository
- Commits
- Commit hash
- Git diff
- Changed files
- Added lines
- Modified lines
- Deleted lines

## Definition

Git is a distributed version-control system used to track changes in source code.

A commit represents a saved version of the project, while `git diff` shows the differences between versions of files.

## Relevance to the Project

The Agentic VAPT system can use Git commits and diffs to identify code changes that need to be analyzed.

### Project Flow

```text
Git Repository
      ↓
Git Commit
      ↓
Git Diff
      ↓
Changed Files
      ↓
Security Analysis
```

---

# 2. tree-sitter

## Definition

tree-sitter is a source-code parsing technology that can analyze programming languages and identify structural elements in source code.

It can identify elements such as:

- Functions
- Variables
- Parameters
- Statements
- Function calls
- Expressions
- Control structures

## Relevance to the Project

The parsed source code can be used to understand program structure and support AST-based analysis and Code Property Graph generation.

### Simplified Flow

```text
Source Code
     ↓
tree-sitter
     ↓
Syntax Structure
     ↓
AST / Code Analysis
```

## Initial Approach

The initial implementation can focus on a limited repository and selected programming languages before expanding to larger multi-language repositories.

---

# 3. Abstract Syntax Tree (AST)

## Definition

An Abstract Syntax Tree (AST) is a structured representation of source code.

Instead of treating source code as plain text, an AST represents the relationships between different code elements.

A simplified AST can contain:

- Functions
- Parameters
- Variables
- Assignments
- Statements
- Expressions
- Function calls
- Return statements

## Example

For:

```python
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
```

The AST can represent the code approximately as:

```text
Module
 └── FunctionDef
      ├── arguments
      │    └── username
      │
      ├── Assign
      │    ├── query
      │    └── Expression
      │
      └── Return
           └── query
```

## Relevance to the Project

AST information can help the VAPT system understand:

- Which functions were changed
- Which variables are involved
- Where user-controlled input is used
- Where security-sensitive operations occur
- How code elements are related

---

# 4. Code Property Graph (CPG)

## Definition

A Code Property Graph (CPG) represents relationships between different elements of source code.

It combines information about program structure, relationships, and data flow.

### Simplified Example

```text
User Input
    ↓
Function A
    ↓
Function B
    ↓
Database Query
```

## Relevance to the Project

CPG can help the system understand how data moves through different parts of an application.

This can support vulnerability analysis by identifying relationships such as:

```text
User Input
     ↓
Variable
     ↓
Function
     ↓
Sensitive Operation
```

---

# 5. Differential CPG

## Definition

Differential CPG focuses security analysis on code changes introduced through Git commits instead of repeatedly analyzing the entire repository.

### Flow

```text
Previous Code
      +
Git Diff
      ↓
Changed Code
      ↓
Updated / Differential CPG
      ↓
Security Analysis
```

## Benefit

If only a small part of a large application changes, analyzing only the affected code can reduce unnecessary processing.

## Initial Limitation

The initial implementation can focus on:

- A single repository
- Limited AST analysis
- Limited CPG scope
- Small code changes

Complex multi-file and large-scale analysis can be added later.

---

# 6. DAST – Dynamic Application Security Testing

## Definition

DAST (Dynamic Application Security Testing) evaluates a running application from an external perspective.

Instead of analyzing only source code, DAST interacts with the running application and observes its behavior and responses.

### Simplified Flow

```text
Running Application
        ↓
DAST Testing
        ↓
Application Responses
        ↓
Potential Findings
```

## Relevance to the Project

DAST can be used to identify vulnerabilities that are observable during application execution.

Examples include:

- Injection vulnerabilities
- Cross-Site Scripting
- Authentication issues
- Security misconfigurations
- Other runtime weaknesses

---

# 7. Docker & Containerized DAST

## Definition

Docker provides isolated containers in which applications, dependencies, and security-testing tools can be executed.

A containerized DAST environment can contain:

- Target application
- Required dependencies
- DAST tools
- Testing configuration

### Flow

```text
Docker Container
       ↓
Target Application
       ↓
DAST Tool
       ↓
Security Results
```

## Project Consideration

Container startup time can introduce additional delay.

Therefore, heavier DAST activities can be executed asynchronously in CI/CD rather than blocking every quick security check.

---

# 8. Local LLM

## Definition

A Local Large Language Model (LLM) is an AI model that runs within a controlled local environment instead of sending data to an external AI service.

Technologies considered include:

- Ollama
- llama.cpp
- vLLM

## Possible AI Responsibilities

The LLM may eventually:

- Analyze security findings
- Interpret security-tool output
- Correlate findings with source code
- Assist with risk analysis
- Recommend the next analysis step
- Produce structured security results

### Project Flow

```text
Security Tool Results
        ↓
     Local LLM
        ↓
   AI Analysis
        ↓
Structured Finding
```

## Technical Consideration

Local LLM performance depends on available CPU, GPU, VRAM, model size, and quantization.

A fallback to dedicated local inference infrastructure can be considered if local hardware becomes a limitation.

---

# 9. Structured AI Output

## Definition

Structured AI output means forcing AI-generated results into a predictable format, such as JSON.

This makes the output easier for other software components to process.

### Example

```json
{
    "finding_type": "SQL Injection",
    "severity": "High",
    "file": "login.py",
    "line": 42,
    "status": "Needs Validation"
}
```

## Project Relevance

Structured output allows different components of the VAPT system to exchange information consistently.

Possible future implementation:

```text
AI Analysis
     ↓
Structured JSON
     ↓
Validation Module
     ↓
Risk Analysis
     ↓
Report Generator
```

JSON schemas or grammar-based constraints can later be used to enforce the expected structure.

---

# 10. Anti-Hallucination / Finding Validation

## Definition

AI hallucination occurs when an AI model produces an incorrect or unsupported result.

In a security system, an AI-generated vulnerability should therefore not automatically be treated as a confirmed vulnerability.

## Example

If the AI reports:

```text
SQL Injection
File: login.py
Line: 42
```

the system should verify that:

- The file actually exists
- The reported line contains the relevant code
- The referenced function exists
- The relevant variable or symbol exists
- Supporting security evidence exists

### Validation Flow

```text
AI Finding
     ↓
Check File
     ↓
Check AST Symbols
     ↓
Check Code Relationships
     ↓
Check Security Evidence
     ↓
Validated / Rejected
```

## Key Understanding

The AI should assist with analysis, but its conclusions should be supported by actual source-code information and security-testing evidence.

---

# 11. SARIF

## Definition

SARIF stands for Static Analysis Results Interchange Format.

It is a standardized format for representing results from static-analysis and security tools.

## Project Relevance

The Agentic VAPT system can eventually generate SARIF files containing machine-readable security findings.

These results can then be consumed by compatible development and CI/CD security platforms.

### Simplified Flow

```text
VAPT Tools
    ↓
Security Findings
    ↓
SARIF
    ↓
CI/CD / Security Platform
```

---

# 12. CI/CD Security Gate

## Definition

A CI/CD security gate integrates security checks into the software-development pipeline.

A security check can determine whether the pipeline should continue or stop based on configured security conditions.

### Simplified Flow

```text
Developer Commit
       ↓
VAPT Security Check
       ↓
Finding Evaluation
       ↓
Pass / Fail
```

A simplified implementation can use:

```text
Exit Code 0 → Pass
Exit Code 1 → Fail
```

This allows security checks to become part of the development workflow.

---

# 13. Coding Practice

Small practical exercises were performed to understand the technologies studied today.

---

## 13.1 Git Diff Practice

### File

```text
git_diff_demo.py
```

### Initial Code

```python
def login(username):
    return username


def search(query):
    return query
```

The initial version was committed to Git to create a baseline.

The `login()` function was then modified.

### Modified Code

```python
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query


def search(query):
    return query
```

The following command was used:

```bash
git diff
```

### Result

Git identified the changed lines.

```text
Old Code
    ↓
return username

New Code
    ↓
SQL query construction using username
```

### Purpose

This exercise demonstrated how Git can identify:

- Modified files
- Added lines
- Removed lines
- Developer-introduced changes

### Project Relevance

The future Differential VAPT module can use Git diff information to identify changed code that requires security analysis.

---

# 13.2 AST Practice

### File

```text
ast_demo.py
```

Python's built-in `ast` module was used to understand how source code can be converted into a structured tree.

### Implementation

```python
import ast

code = """
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
"""

tree = ast.parse(code)

print("AST Structure:")
print(ast.dump(tree, indent=2))
```

### Output

The program generated an AST containing nodes such as:

```text
Module
  FunctionDef
    arguments
      arg
    Assign
      Name
      BinOp
    Return
      Name
```

### Purpose

The exercise helped understand how source code can be represented using:

- Functions
- Arguments
- Assignments
- Variables
- Expressions
- Return statements

### Project Relevance

AST analysis can later support:

- Source-code security analysis
- Code structure understanding
- Data-flow analysis
- CPG generation

---

# 13.3 Structured Vulnerability JSON Practice

### File

```text
finding.json
```

A sample vulnerability finding was represented using JSON.

### Implementation

```json
{
    "finding_type": "SQL Injection",
    "severity": "High",
    "file": "login.py",
    "line": 2,
    "status": "Needs Validation"
}
```

### Fields

| Field | Purpose |
|---|---|
| `finding_type` | Type of security issue |
| `severity` | Risk level |
| `file` | File associated with the finding |
| `line` | Relevant source-code line |
| `status` | Current validation status |

### Purpose

This exercise demonstrated how security findings can be stored in a structured format.

### Project Relevance

A similar structure can later be used for communication between different components of the VAPT system.

---

# 13.4 Reading Structured Security Findings

### File

```text
read_finding.py
```

### Implementation

```python
import json
import os

file_path = os.path.join(os.path.dirname(__file__), "finding.json")

with open(file_path, "r") as file:
    finding = json.load(file)

print("Security Finding")
print("-----------------")
print("Type:", finding["finding_type"])
print("Severity:", finding["severity"])
print("File:", finding["file"])
print("Line:", finding["line"])
print("Status:", finding["status"])
```

### Execution

```bash
python Day-02\read_finding.py
```

### Output

```text
Security Finding
-----------------
Type: SQL Injection
Severity: High
File: login.py
Line: 2
Status: Needs Validation
```

### Purpose

This exercise demonstrated how a Python module can read and process structured vulnerability information.

### Project Relevance

Different modules of the future VAPT system can exchange security findings using structured data.

---

# 14. Overall Technology Flow

The technologies studied today can be connected as follows:

```text
Git Repository
      ↓
Git Diff
      ↓
tree-sitter
      ↓
AST / CPG
      ↓
Security Testing / DAST
      ↓
Security Findings
      ↓
Local LLM
      ↓
AI Analysis
      ↓
Evidence Validation
      ↓
Risk Analysis
      ↓
CI/CD / Dashboard / Report
```

This represents the proposed direction of the Agentic VAPT system.

---

# 15. Feasibility Considerations Studied

| Component | Main Risk | Initial Mitigation |
|---|---|---|
| Differential CPG | Complex code changes may increase analysis time | Start with limited AST/CPG scope |
| Containerized DAST | Container startup delay | Run heavy DAST asynchronously |
| Local LLM | Hardware / VRAM limitations | Consider optimized or dedicated local inference |
| OSS Tools | License compatibility | Review licenses before integration |
| AI Analysis | Hallucinated findings | Verify claims using code and security evidence |

---

# 16. Data Requirements – Initial Understanding

The proposed system may eventually require the following inputs:

## Git Repository Data

- Git commits
- Commit hashes
- Git diffs
- Changed files
- Source files
- File trees
- Commit metadata

## Source-Code Analysis Data

- Parsed source code
- AST information
- Symbols
- Function relationships
- Data-flow information
- CPG information

## Security Testing Data

- DAST results
- Security-tool output
- Endpoint information
- Application responses
- Vulnerability findings

## AI / Inference Data

- Security findings
- Source-code context
- Structured prompts
- JSON schemas
- Model configuration

## Project Configuration

- Docker configuration
- Application configuration
- Testing configuration
- Security rules

---

# 17. Expected System Outputs

The future system may produce:

- Security findings
- Risk scores
- Vulnerability reports
- Structured JSON results
- SARIF results
- CI/CD pass/fail decisions
- Validation results
- Remediation suggestions
- Audit reports
- Dashboard information

---

# 18. Day 2 Responsibilities / Implementation Understanding

The major implementation responsibilities identified for the project are:

```text
Git Integration
      ↓
Identify Code Changes
      ↓
Parse Changed Code
      ↓
Build AST / CPG Information
      ↓
Run Security Tests
      ↓
Collect Findings
      ↓
AI Analysis
      ↓
Validate Findings
      ↓
Risk Analysis
      ↓
Generate Results
```

The Day 2 practical exercises covered the early building blocks of this workflow.

---

# 19. Day 2 Key Learnings

- Understood how Git diffs can be used as an input for security analysis.
- Learned the basic purpose of tree-sitter.
- Learned how AST represents source-code structure.
- Understood the purpose of CPG.
- Understood the purpose of Differential CPG.
- Learned the difference between source-code analysis and DAST.
- Understood the role of Docker in isolated DAST execution.
- Studied the possible use of local LLMs for security analysis.
- Understood the importance of structured AI output.
- Learned why AI-generated findings need validation.
- Studied the basic role of SARIF.
- Studied the concept of CI/CD security gates.
- Practiced Git diff analysis using a Python example.
- Practiced generating and inspecting an AST using Python.
- Practiced creating structured vulnerability information using JSON.
- Practiced reading structured vulnerability information using Python.
- Understood the major technical risks associated with the proposed architecture.

---

# 20. Day 2 Outcome

Developed a basic technical understanding of the major technologies and components required for the proposed Agentic VAPT system.

The practical exercises provided initial hands-on experience with:

```text
Git Change Tracking
        +
AST Analysis
        +
Structured Security Findings
```

These concepts provide the foundation for the later implementation of the Agentic VAPT pipeline.

---

# Next Steps

- Explore Git diff processing programmatically.
- Study source-code parsing using tree-sitter.
- Explore AST-to-CPG concepts.
- Explore security-tool integration.
- Study DAST execution and result handling.
- Explore Docker-based testing environments.
- Study local LLM integration.
- Design communication between VAPT modules.
- Explore structured security-result formats.
- Begin developing module-level proof-of-concepts.