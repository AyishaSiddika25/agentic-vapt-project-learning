# Day 5 – Connecting Git Diff with Source-Code Parsing (Differential Analysis)

## Objective

The objective of Day 5 was to connect the concepts learned in the previous days:

* **Git Diff and Change Scoping** from Day 4
* **Python AST and Source-Code Parsing** from Day 2 and Day 3

The goal was to build a small **Differential Code Analysis** proof of concept that can identify:

1. Which Python files were changed
2. Which lines were changed
3. Which functions contain those changed lines
4. Whether the affected functions contain security-relevant code
5. Which functions should be included in the security analysis scope

The implemented workflow is:

```text
Git Diff
   |
   v
Changed Python Files
   |
   v
Changed Line Numbers
   |
   v
Python AST
   |
   v
Affected Functions
   |
   v
Security-Relevance Check
   |
   v
Security Analysis Scope
```

---

# 1. Why Differential Analysis?

Traditional security analysis may scan an entire application whenever a change is made.

For a large application, this can be inefficient because most of the code may not have changed.

Differential analysis focuses security analysis on the code affected by a recent change.

For example:

```text
Application
│
├── authentication.py
├── users.py
├── payments.py       ← changed
├── reports.py
└── dashboard.py
```

Instead of analyzing the entire application:

```text
Entire Application
        |
        v
Security Analysis
```

we can identify the changed area:

```text
Git Diff
   |
   v
payments.py
   |
   v
process_payment()
   |
   v
Security Analysis
```

This can reduce unnecessary analysis and provide a more targeted security-testing workflow.

---

# 2. Connection with Previous Days

Day 5 combines the concepts learned previously.

### Day 2 – Git, AST and Security Findings

Learned:

* Git basics
* Git change tracking
* Python AST
* Structured security findings
* Security analysis concepts

### Day 3 – Source-Code Parsing

Learned:

* Source-code parsing
* Tree-sitter
* Syntax trees
* Functions
* Variables
* Statements
* Code structure

### Day 4 – Git Diff Analysis

Learned:

* `git diff`
* Changed files
* Changed lines
* Change scoping
* Security analysis of modified code

### Day 5 – Differential Analysis

Connected these concepts:

```text
Day 4
Git Diff
   |
   v
Changed Code
   |
   |
Day 3
   v
AST / Code Structure
   |
   v
Affected Functions
   |
   v
Security Analysis Scope
```

---

# 3. Day 5 Architecture

The implemented proof of concept follows this architecture:

```text
                 Git Repository
                       |
                       v
                   git diff
                       |
                       v
             Changed Python Files
                       |
                       v
              Changed Line Numbers
                       |
                       v
                  Python AST
                       |
                       v
              Affected Functions
                       |
                       v
           Security-Relevance Check
                       |
                       v
            Security Analysis Scope
                       |
                       v
               Analysis Required
```

---

# 4. Project Structure

The Day-05 implementation contains:

```text
Day-05/
│
├── payment.py
│
└── differential_analysis.py
```

### `payment.py`

Contains the sample application code used to create a meaningful Git change.

### `differential_analysis.py`

Contains the Python implementation for:

* Git diff detection
* Changed-line extraction
* AST parsing
* Function identification
* Security-relevance checking
* Security analysis scoping

---

# 5. Sample Application

The sample application contains two functions:

```python
def process_payment(amount):
    query = "SELECT * FROM payments WHERE amount=" + str(amount)
    return query


def get_payment_status(payment_id):
    return "Payment status for " + payment_id
```

The `process_payment()` function was modified to introduce a dynamically constructed SQL query.

This is intentionally used as a **security-analysis example** so that the differential analyzer has security-relevant code to identify.

> Note: This Day-05 project does not perform an actual SQL injection exploit. It identifies the changed function as security-relevant and places it in the security analysis scope.

---

# 6. Git Diff

The original version contained:

```python
def process_payment(amount):
    return amount
```

The modified version contains:

```python
def process_payment(amount):
    query = "SELECT * FROM payments WHERE amount=" + str(amount)
    return query
```

The Git diff is:

```diff
 def process_payment(amount):
-    return amount
+    query = "SELECT * FROM payments WHERE amount=" + str(amount)
+    return query
```

Git therefore identifies the modified code.

---

# 7. Step 1 – Detect Changed Python Files

The implementation uses Python's `subprocess` module to execute:

```bash
git diff --name-only
```

The function:

```python
def get_changed_files():
    result = subprocess.run(
        ["git", "diff", "--name-only"],
        capture_output=True,
        text=True,
        check=True
    )

    files = result.stdout.strip().splitlines()

    python_files = [
        file for file in files
        if file.endswith(".py")
    ]

    return python_files
```

The result is filtered to include only Python files.

Example:

```text
Changed Python Files:
- Day-05/payment.py
```

This prevents non-Python files from being passed to the Python AST parser.

---

# 8. Step 2 – Identify Changed Line Numbers

The next step extracts the changed line numbers from the Git diff.

The implementation executes:

```bash
git diff --unified=0 -- <file>
```

The `--unified=0` option reduces the diff context so that the changed sections can be identified more precisely.

The implementation looks for Git hunk headers such as:

```text
@@ -1,2 +1,3 @@
```

The `+` section represents the new version of the file.

The function:

```python
def get_changed_line_numbers(file_path):
```

extracts the starting line and number of changed lines.

For the sample change, the analyzer identifies:

```text
Changed Line Numbers:
- Line 2
- Line 3
```

---

# 9. Step 3 – Parse the Source Code with AST

After identifying the changed lines, the analyzer parses the current Python source code using the built-in Python `ast` module.

```python
tree = ast.parse(source_code)
```

The AST provides structural information about the source code.

For example:

```text
payment.py
   |
   +-- process_payment()
   |       |
   |       +-- assignment
   |       +-- SQL query
   |       +-- return
   |
   +-- get_payment_status()
           |
           +-- return
```

---

# 10. Step 4 – Identify Affected Functions

The analyzer walks through the AST:

```python
for node in ast.walk(tree):
```

It looks for:

```python
ast.FunctionDef
ast.AsyncFunctionDef
```

Each function has:

```python
node.lineno
node.end_lineno
```

These values provide the beginning and ending line of the function.

The analyzer compares the changed line numbers with the function boundaries.

Conceptually:

```text
Changed Line
     |
     v
Is line between function start and end?
     |
    YES
     |
     v
Affected Function
```

For the sample:

```text
Changed Lines:
2
3

Function:
process_payment()
Lines:
1–3

Result:
process_payment() is affected
```

The output becomes:

```text
Affected Functions:
- process_payment()
```

---

# 11. Step 5 – Security-Relevance Check

After identifying affected functions, the analyzer performs a basic security-relevance check.

The current prototype uses security-related keywords:

```python
security_keywords = [
    "sql",
    "query",
    "execute",
    "password",
    "token",
    "user",
    "input",
    "request"
]
```

The source code of each affected function is extracted using:

```python
ast.get_source_segment(
    source_code,
    node
)
```

The function source is converted to lowercase and checked against the keywords.

For example:

```python
def process_payment(amount):
    query = "SELECT * FROM payments WHERE amount=" + str(amount)
    return query
```

contains:

```text
query
sql
```

Therefore it is classified as security-relevant by the prototype.

---

# 12. Security Analysis Scope

The final scope is:

```text
Security Analysis Scope:
- process_payment()

Analysis Required: YES
```

The important concept is that the entire application does not need to be treated equally.

The analyzer identifies:

```text
Changed File
     |
     v
payment.py
     |
     v
Changed Lines
     |
     v
process_payment()
     |
     v
Security-Relevant
     |
     v
Analysis Required
```

---

# 13. Complete Data Flow

The complete Day-05 proof of concept can be represented as:

```text
Developer Changes Code
        |
        v
      Git
        |
        v
    git diff
        |
        v
Changed Python Files
        |
        v
Changed Line Numbers
        |
        v
Current Source Code
        |
        v
    Python AST
        |
        v
Function Boundaries
        |
        v
Affected Functions
        |
        v
Security-Relevance Check
        |
        v
Security Analysis Scope
        |
        v
Analysis Required
```

---

# 14. Example Output

A typical result for the sample application is:

```text
========================================
Differential Code Analysis
========================================

Changed Python Files:
- Day-05/payment.py

========================================
Changed File: Day-05/payment.py
========================================

Changed Line Numbers:
- Line 2
- Line 3

Affected Functions:
- process_payment()

Security-Relevant Functions:
- process_payment()

Security Analysis Scope:
- process_payment()

Analysis Required: YES
```

---

# 15. Why This Is Useful for Agentic VAPT

The differential-analysis layer can become an important component of the Agentic VAPT architecture.

Instead of sending an entire repository to security scanners or an LLM, the system can first identify the relevant changed code.

For example:

```text
Git Commit
    |
    v
Git Diff
    |
    v
Changed Code
    |
    v
Differential Analysis
    |
    v
Affected Functions
    |
    v
Security-Relevant Scope
    |
    +------------------+
    |                  |
    v                  v
Security Scanner      LLM
    |                  |
    +--------+---------+
             |
             v
       Security Findings
             |
             v
        Validation
             |
             v
       Risk Analysis
             |
             v
          Report
```

This approach can help reduce unnecessary analysis of unchanged code.

---

# 16. Real-World Example – E-Commerce Payment System

Consider an e-commerce application containing:

```text
payments/
├── payment.py
├── refund.py
├── invoice.py
└── payment_history.py
```

A developer changes:

```python
def process_payment(amount):
    query = "SELECT * FROM payments WHERE amount=" + str(amount)
```

Git detects the change.

The differential-analysis system can determine:

```text
Changed File:
payment.py

Affected Function:
process_payment()

Security-Relevant:
YES

Security Analysis:
REQUIRED
```

The Agentic VAPT system could then pass this function to security-testing components such as:

```text
Semgrep
   |
   v
Security Finding
   |
   v
Evidence Validation
   |
   v
LLM Triage
   |
   v
Risk Analysis
```

The rest of the unchanged payment application does not necessarily need the same level of immediate analysis.

---

# 17. Relation to Differential CPG

Differential Code Analysis is also a foundation for the more advanced **Differential Code Property Graph (Differential CPG)** concept discussed earlier.

The conceptual progression is:

```text
Git Diff
   |
   v
Changed Code
   |
   v
AST
   |
   v
Code Relationships
   |
   v
CPG
   |
   v
Differential CPG
   |
   v
Security Analysis
```

A Differential CPG can eventually represent changes together with structural relationships such as:

* Function relationships
* Call relationships
* Data flow
* Control flow
* Dependency relationships

The current Day-05 implementation does **not** build a CPG yet. It establishes the earlier and simpler stage:

```text
Git Diff → Changed Lines → AST → Affected Functions
```

---

# 18. Limitations of the Current Prototype

The current implementation is intentionally a small proof of concept.

### 1. Python Only

The analyzer currently filters for:

```text
.py
```

Other languages are not supported.

### 2. Basic Security-Relevance Detection

The current implementation uses keyword matching:

```text
sql
query
execute
password
token
user
input
request
```

This is not a complete vulnerability detector.

For example, a function containing the word `query` is not automatically vulnerable.

### 3. No Data-Flow Analysis

The prototype does not determine whether untrusted input actually reaches a sensitive operation.

### 4. No Call-Graph Analysis

The implementation currently identifies functions containing changed lines but does not trace:

```text
Function A
    ↓
Function B
    ↓
Database
```

### 5. No CPG

A Code Property Graph has not yet been implemented.

### 6. No LLM Integration

The current implementation does not send findings or source code to an LLM.

### 7. No Exploit Validation

The system does not execute an exploit or verify whether the suspected vulnerability is actually exploitable.

### 8. Git Diff Scope

The current proof of concept works with the Git working-tree diff and is designed for the controlled Day-05 demonstration.

---

# 19. Future Improvements

The Day-05 prototype can be extended in later stages.

### Source-Code Analysis

Replace or complement Python AST with:

```text
Tree-sitter
```

to support multiple programming languages.

### Dependency Analysis

Add:

```text
Call Graph
Dependency Graph
Data Flow
Control Flow
```

### CPG Integration

Build:

```text
AST + CFG + DFG
       |
       v
      CPG
```

and eventually:

```text
Previous CPG
     +
Git Diff
     |
     v
Differential CPG
```

### Security Scanner Integration

The scoped functions can be passed to tools such as:

```text
Semgrep
Gitleaks
OSV-Scanner
Trivy
Checkov
```

depending on the type of code and security requirement.

### LLM Analysis

The scoped code can eventually be provided to an LLM for:

* Vulnerability triage
* Finding explanation
* Risk reasoning
* Attack-path hypothesis
* Evidence analysis

### Validation

AI-generated hypotheses should be validated using deterministic security tools or controlled testing.

---

# 20. Connection to the Full Agentic VAPT Pipeline

The long-term architecture discussed throughout the VAPT project is:

```text
Git Repository
      |
      v
   Git Diff
      |
      v
Changed Code
      |
      v
Tree-sitter / AST
      |
      v
AST / CPG
      |
      v
Security Testing / DAST
      |
      v
Security Findings
      |
      v
Local / External LLM
      |
      v
AI Analysis
      |
      v
Evidence Validation
      |
      v
Risk Analysis
      |
      v
CI/CD / Dashboard / Report
```

Day 5 implemented an important early portion of this architecture:

```text
Git Repository
      |
      v
   Git Diff
      |
      v
Changed Code
      |
      v
Python AST
      |
      v
Affected Functions
      |
      v
Security Analysis Scope
```

---

# 21. Key Learnings

Through this implementation, I learned:

* How to execute Git commands from Python using `subprocess`
* How to detect changed files programmatically
* How to extract changed line numbers from Git diff hunks
* How Git diff can be connected with source-code analysis
* How Python AST represents source-code structure
* How AST function boundaries can be used to map changed lines to functions
* How changed functions can be prioritized for security analysis
* Why differential analysis is useful for large applications
* Why unchanged code does not always need the same immediate security-analysis priority
* How Git Diff and AST can form the foundation of a differential security-analysis pipeline
* How this approach can later evolve toward CPG and Differential CPG
* Why security keyword matching is only an initial heuristic and not a complete vulnerability-detection method
* Why evidence validation is necessary before treating a suspected finding as a confirmed vulnerability

---

# 22. Day 5 Implementation Status

**Status:** Completed

### Implemented

* Git diff integration
* Changed Python file detection
* Changed line-number extraction
* Python AST parsing
* Affected function identification
* Security-relevance heuristic
* Security analysis scope generation
* Multiple-file capable Python-file discovery

### Not Yet Implemented

* Tree-sitter integration
* CPG generation
* Differential CPG
* Data-flow analysis
* Call-graph analysis
* Semgrep integration
* DAST integration
* LLM analysis
* Exploit validation
* Automated SARIF generation
* CI/CD security gate

These are future stages of the Agentic VAPT project.

---

# 23. Day 5 Final Workflow

```text
                    DAY 5
                      |
                      v
                Git Repository
                      |
                      v
                   Git Diff
                      |
                      v
            Changed Python Files
                      |
                      v
             Changed Line Numbers
                      |
                      v
                 Python AST
                      |
                      v
             Affected Functions
                      |
                      v
          Security-Relevance Check
                      |
                      v
            Security Analysis Scope
                      |
                      v
              Analysis Required
```

### Final Concept

The main concept learned on Day 5 is:

> **Git identifies what changed; AST identifies what that change means structurally; differential analysis uses both to narrow the security-analysis scope.**
