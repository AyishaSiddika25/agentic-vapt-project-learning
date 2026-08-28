# Day 02 – Technologies, Tools & Coding Practice

## Objective

The objective of Day 2 was to study the major technologies and components proposed for the AI-Powered Agentic VAPT system and understand how they fit into the overall architecture.

Along with theoretical learning, small coding exercises were performed to understand Git-based change tracking, source-code structure using AST, and structured vulnerability data.

---

## 1. Git Integration

Git was studied as the source and change-tracking mechanism for the project.

### Key Concepts Learned

- Git repository
- Commits
- Commit hash
- Git diff
- Changed files
- Added, modified, and deleted lines

### Relevance to the Project

Git commits and diffs can be used to identify code changes that need to be analyzed by the VAPT system.

**Git Repository → Git Commit → Git Diff → Changed Files → Security Analysis**

---

## 2. tree-sitter

tree-sitter was studied as a source-code parsing technology.

It can analyze source code and identify structural elements such as:

- Functions
- Variables
- Parameters
- Statements
- Function calls
- Expressions

### Relevance to the Project

The parsed source code can be used to generate an Abstract Syntax Tree (AST), which can support code-level security analysis and Code Property Graph generation.

**Source Code → tree-sitter → AST → Code Analysis**

---

## 3. Abstract Syntax Tree (AST)

An Abstract Syntax Tree represents the structural elements of source code.

A simplified structure can contain:

- Functions
- Parameters
- Variables
- Statements
- Function calls

### Relevance to the Project

AST information can help the system understand:

- Which functions were changed
- Which variables are involved
- How functions are connected
- Where user-controlled input may flow
- Where security-sensitive operations occur

---

## 4. Code Property Graph (CPG)

A Code Property Graph represents relationships within source code.

A simplified example is:

**User Input → Function A → Function B → Database Query**

### Relevance to the Project

CPG can help identify relationships between different code components and support vulnerability analysis.

---

## 5. Differential CPG

Differential CPG was studied as an approach for focusing analysis on code changes introduced through Git commits instead of repeatedly analyzing the complete repository.

**Previous Code + Git Diff → Changed Code → Updated / Differential CPG → Security Analysis**

### Benefit

This approach can reduce unnecessary analysis and improve efficiency when only a small part of a large repository has changed.

### Initial Limitation

The initial implementation can focus on a single repository and a limited AST/CPG scope before expanding to complex multi-file analysis.

---

## 6. DAST – Dynamic Application Security Testing

DAST was studied as a method for evaluating a running application from an external perspective.

**Application → Running Environment → DAST Testing → Observed Responses → Potential Findings**

DAST can be used to identify vulnerabilities that are observable during application execution.

---

## 7. Docker & Containerized DAST

Docker was studied as a possible way to provide an isolated environment for running the target application and DAST tests.

A Docker environment can contain:

- Target application
- Required dependencies
- DAST testing tools

### Project Consideration

Container startup time may introduce delays. Therefore, heavier DAST activities can be considered for asynchronous CI/CD execution rather than blocking every quick security check.

---

## 8. Local LLM

The project proposes using a locally hosted Large Language Model for security analysis.

Possible technologies studied included:

- Ollama
- llama.cpp
- vLLM

### Possible AI Responsibilities

- Analyze security findings
- Interpret tool output
- Correlate findings with code
- Assist with risk analysis
- Recommend the next appropriate analysis step
- Produce structured security results

**Security Tool Results → Local LLM → AI Analysis → Structured Finding**

---

## 9. Structured AI Output

Structured AI output was studied as a way to make LLM results more predictable and easier for other components to process.

Example structure:

```json
{
  "finding_type": "SQL Injection",
  "severity": "High",
  "file": "login.py",
  "line": 42,
  "status": "Needs Validation"
}
```

JSON schemas or grammar-based constraints can be used to control the format of AI-generated results.

---

## 10. Anti-Hallucination

The importance of validating AI-generated security findings was studied.

For example, if an AI model reports a vulnerability in a particular file and line, the system should verify the claim against actual code and security evidence.

Possible validation flow:

**AI Finding → Check File → Check AST Symbols → Check Code Relationship → Check Security Evidence → Validated / Rejected**

### Key Understanding

The AI should not be treated as the final source of truth. Its conclusions should be supported by actual source-code information and security-testing evidence.

---

## 11. SARIF

SARIF was studied as a standardized format for representing static-analysis and security results.

The system can eventually generate a SARIF file containing machine-readable security findings.

This can allow security findings to be consumed by compatible development and CI/CD security platforms.

---

## 12. CI/CD Security Gate

The concept of integrating VAPT into the development pipeline was studied.

Simplified flow:

**Developer Commit → VAPT Security Check → Finding Evaluation → Pass / Fail**

A successful check can allow the pipeline to continue, while a configured security failure can block the process.

- Exit code 0 → Pass
- Exit code 1 → Fail

---

# 13. Coding Practice

Small practical exercises were performed to understand the technologies studied today.

## 13.1 Git Diff Practice

A simple Python file was created:

```python
def login(username):
    return username
```

The code was then modified:

```python
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
```

The following command was used to inspect the changes:

```bash
git diff
```

### Purpose

This exercise helped understand how Git can identify:

- Modified files
- Added lines
- Removed lines
- Changes introduced by a developer

### Project Relevance

The future VAPT system can use Git diff information to identify changed code that requires security analysis.

---

## 13.2 AST Practice

Python's built-in `ast` module was used to understand how source code can be represented as a structured tree.

Example:

```python
import ast

code = """
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
"""

tree = ast.parse(code)

print(ast.dump(tree, indent=2))
```

### Purpose

The exercise was used to understand how source code can be converted into a structured representation containing elements such as:

- Functions
- Arguments
- Assignments
- Variables
- Expressions
- Function calls

### Project Relevance

AST analysis can later support source-code security analysis and CPG generation.

---

## 13.3 Structured Vulnerability JSON Practice

A sample vulnerability finding was represented using JSON.

### `finding.json`

```json
{
    "finding_type": "SQL Injection",
    "severity": "High",
    "file": "login.py",
    "line": 2,
    "status": "Needs Validation"
}
```

A Python script was used to read and process the structured finding:

```python
import json

with open("finding.json", "r") as file:
    finding = json.load(file)

print("Finding:", finding["finding_type"])
print("Severity:", finding["severity"])
print("File:", finding["file"])
print("Line:", finding["line"])
print("Status:", finding["status"])
```

### Purpose

This exercise helped understand how vulnerability information can be stored in a structured format.

### Project Relevance

A similar structured format can later be used for communication between different components of the VAPT system.

---

# 14. Overall Technology Flow

The technologies studied today can be connected as follows:

**Git Repository → Git Diff → tree-sitter → AST / CPG → Security Testing / DAST → Security Findings → Local LLM → AI Analysis → Evidence Validation → Risk Analysis → CI/CD / Dashboard / Report**

---

# 15. Feasibility Considerations Studied

| Component | Main Risk | Initial Mitigation |
|---|---|---|
| Differential CPG | Complex code changes may increase analysis time | Start with limited AST/CPG scope |
| Containerized DAST | Container startup delay | Run heavy DAST asynchronously |
| Local LLM | Hardware/VRAM limitations | Consider dedicated local inference |
| OSS Tools | License compatibility | Review licenses before integration |
| AI Analysis | Hallucinated findings | Verify claims using code and evidence |

---

# 16. Day 2 Key Learnings

- Understood how Git diffs can be used as an input for security analysis.
- Learned the basic purpose of tree-sitter and AST.
- Understood the purpose of CPG and Differential CPG.
- Learned the difference between source-code analysis and DAST.
- Understood the role of Docker in isolated DAST execution.
- Studied the use of local LLMs for security analysis.
- Understood why structured AI output is important.
- Learned the importance of validating AI-generated security findings.
- Studied the basic role of SARIF and CI/CD security gates.
- Practiced Git diff analysis.
- Practiced generating and inspecting an AST using Python.
- Practiced creating and processing structured vulnerability JSON.
- Understood the major technical risks associated with the proposed architecture.

---

# 17. Day 2 Outcome

Developed a basic technical understanding of the major tools and technologies required for the proposed Agentic VAPT system.

The coding exercises provided initial hands-on experience with Git change tracking, source-code structure analysis, and structured vulnerability data, which are relevant foundations for the later implementation of the project.

---

# Next Steps

- Explore the selected technologies through larger proof-of-concept implementations.
- Study the data formats exchanged between the different modules.
- Understand how Git diffs can be converted into AST/CPG information.
- Explore security-tool and DAST integration.
- Study the approach for connecting a local LLM with the VAPT workflow.
- Begin developing small module-level proof of concepts.
