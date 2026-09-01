# Day 4 – Git Diff Analysis & Change Scoping

## Objective

Today I learned how Git changes can be analyzed to identify which files and lines were modified in a commit.

This is important for the **Agentic VAPT** project because the system should not unnecessarily analyze the entire repository on every code change.

Instead, security analysis can be scoped to:

```text
Changed Files
      +
Changed Code
      +
Relevant Dependents
```

This makes the security analysis more focused, efficient, and suitable for integration into a CI/CD pipeline.

---

# 1. What is Git Diff?

A Git diff shows the changes made between two versions of code.

It can show:

* Added lines
* Deleted lines
* Modified lines
* Changed files
* Location of changes
* Context around the changes

### Basic Flow

```text
Old Code
   ↓
Developer Change
   ↓
New Code
   ↓
Git Diff
   ↓
Identify Changes
```

### Example

```diff
 def login(username):
-    return username
+    query = "SELECT * FROM users WHERE name='" + username + "'"
+    return query
```

The symbols mean:

```text
-  → Removed line
+  → Added line
```

Git diff therefore gives us a deterministic way to identify what changed in a commit.

---

# 2. Why Git Diff Matters in Agentic VAPT

A major goal of Agentic VAPT is to avoid unnecessarily analyzing the entire repository for every small code change.

The detection process can instead begin with the changed area.

### Traditional Approach

```text
Entire Repository
        ↓
Run Security Scanners
        ↓
Large Amount of Code
        ↓
Large Number of Findings
        ↓
More Processing
```

### Change-Aware Approach

```text
Git Commit
     ↓
Git Diff
     ↓
Changed Files
     ↓
Changed Code
     ↓
Relevant Dependents
     ↓
Security Analysis
```

The second approach allows the system to focus its initial analysis on the code affected by the current change.

---

# 3. What is Change Scoping?

**Change scoping** means identifying the portion of an application that may have been affected by a code change.

For example:

```text
Repository
│
├── auth/
│   ├── login.py
│   └── register.py
│
├── payments/
│   ├── payment.py
│   └── refund.py
│
├── database/
│   └── db.py
│
├── users/
│   └── profile.py
│
└── config/
    └── settings.py
```

Suppose a developer modifies only:

```text
payments/payment.py
```

The initial analysis can focus on:

```text
payments/payment.py
        ↓
Changed Functions
        ↓
Changed Code
        ↓
Relevant Dependencies
        ↓
Security Analysis
```

The purpose is **not** to permanently ignore the rest of the repository.

The purpose is to determine which parts require immediate security analysis because of the current change.

---

# 4. Why Dependents Matter

Looking only at the changed file may not always be sufficient.

A changed function may affect other parts of the application.

For example:

```text
payment.py
     ↓
process_payment()
     ↓
database.py
     ↓
db.query()
```

If `process_payment()` changes how data is passed to `db.query()`, the dependent code may also become relevant.

Therefore, the broader concept is:

```text
Changed Files
      ↓
Changed Functions
      ↓
Dependencies / Dependents
      ↓
Affected Code Area
```

This becomes particularly useful when the Agentic VAPT system later uses a **code dependency graph**.

---

# 5. Git Diff and Security Analysis

Consider this code change:

```diff
 def login(username):
-    return username
+    query = "SELECT * FROM users WHERE name='" + username + "'"
+    return query
```

A developer has introduced a SQL query using string concatenation.

The security-analysis pipeline can identify:

```text
Git Diff
    ↓
New SQL-related Code
    ↓
Changed Function
    ↓
Security Analysis
```

A deterministic scanner such as Semgrep can then analyze the relevant code.

For example:

```text
Changed Function
       ↓
Semgrep
       ↓
Potential Security Finding
       ↓
SARIF Result
```

The finding can then move into later stages of the Agentic VAPT workflow.

---

# 6. Git Diff + Tree-sitter

Day 3 introduced **Tree-sitter** for understanding source-code structure.

Day 4 connects Git changes with that structure.

Git and Tree-sitter answer different questions.

### Git Diff

```text
What changed?
```

### Tree-sitter

```text
What is the structure of the changed code?
```

Together:

```text
Git Diff
   ↓
Changed File
   ↓
Tree-sitter
   ↓
Syntax Tree
   ↓
Changed Function / Code Structure
   ↓
Security Analysis
```

This provides both:

```text
Change Information
        +
Code Structure
```

---

# 7. Example: Git Diff + Tree-sitter

Suppose the original code is:

```python
def login(username):
    return username
```

The developer changes it to:

```python
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
```

Git identifies the change:

```diff
 def login(username):
-    return username
+    query = "SELECT * FROM users WHERE name='" + username + "'"
+    return query
```

Tree-sitter can then represent the code structurally:

```text
function_definition
    ↓
login
    ↓
assignment
    ↓
string / expression
    ↓
return_statement
```

The security pipeline now has:

```text
Git
 ↓
Change Information

Tree-sitter
 ↓
Code Structure
```

This combination provides a better foundation for security analysis than treating the source code as plain text alone.

---

# 8. Real-World Application Example

Consider a large e-commerce application.

The repository contains:

```text
ecommerce-app/
│
├── auth/
│   ├── login.py
│   └── register.py
│
├── payments/
│   ├── payment.py
│   └── refund.py
│
├── database/
│   └── db.py
│
├── users/
│   └── profile.py
│
└── config/
    └── settings.py
```

A developer makes a commit that modifies:

```text
payments/payment.py
```

### Traditional Full-Repository Scan

```text
Entire Repository
        ↓
Semgrep
OSV-Scanner
Trivy
Gitleaks
Checkov
        ↓
Large Number of Results
        ↓
More Processing
```

Instead, the change-aware approach starts with:

```text
Developer Commit
       ↓
Git Diff
       ↓
payments/payment.py
       ↓
Changed Functions
       ↓
Relevant Dependents
       ↓
Security Detection
```

---

# 9. Real-World Security Example

Suppose the original payment function is:

```python
def process_payment(user_id, amount):
    return payment_gateway.charge(user_id, amount)
```

The developer changes it to:

```python
def process_payment(user_id, amount):
    query = "SELECT card_number FROM cards WHERE user_id='" + user_id + "'"
    return payment_gateway.charge(user_id, amount)
```

Git diff identifies:

```diff
 def process_payment(user_id, amount):
-    return payment_gateway.charge(user_id, amount)
+    query = "SELECT card_number FROM cards WHERE user_id='" + user_id + "'"
+    return payment_gateway.charge(user_id, amount)
```

The system can now narrow the analysis to:

```text
payments/payment.py
        ↓
process_payment()
        ↓
New SQL query
        ↓
String concatenation
        ↓
Security Detection
```

A security scanner may identify the pattern as potentially related to SQL injection.

The important point is that the system first identifies **where the change occurred** before performing deeper analysis.

---

# 10. Complete Change-Aware VAPT Flow

The Day 4 concept fits into the larger Agentic VAPT architecture as follows:

```text
Developer Commit
       ↓
Git Diff
       ↓
Identify Changed Files
       ↓
Change Scoping
       ↓
Identify Changed Functions
       ↓
Tree-sitter
       ↓
Understand Code Structure
       ↓
Identify Relevant Dependents
       ↓
Security Detection
       ↓
SARIF Findings
       ↓
Gate
       ↓
LLM Triage
       ↓
Exploit Validation
       ↓
Human Review
       ↓
Rule Generation
       ↓
Reporting
```

This is the connection between today's Git learning and the overall VAPT project.

---

# 11. Git Commands Used

## Check Repository Status

```bash
git status
```

This shows:

* Current branch
* Modified files
* Untracked files
* Staged changes

---

## View Changes

```bash
git diff
```

This displays changes that have not yet been staged.

---

## View Staged Changes

```bash
git diff --cached
```

This shows changes that have already been staged.

---

## View Changed Files

```bash
git diff --name-only
```

This displays the names of changed files.

Example:

```text
Day-04/sample_code.py
```

---

## View a Commit

```bash
git show
```

This displays information about a commit and its changes.

---

# 12. Reading Git Diff Programmatically

Python can execute Git commands and read their output.

Example:

```python
import subprocess


result = subprocess.run(
    ["git", "diff", "--name-only"],
    capture_output=True,
    text=True
)


print("Changed files:")
print(result.stdout)
```

This program asks Git for the names of files that currently have unstaged changes.

---

# 13. Understanding the Python Code

## `subprocess.run()`

Python's `subprocess` module can execute external commands.

Here:

```python
subprocess.run(...)
```

executes:

```text
git diff --name-only
```

---

## `capture_output=True`

This captures the command's output so Python can read it.

---

## `text=True`

This tells Python to return the output as text rather than bytes.

---

## `result.stdout`

This contains the output produced by Git.

---

# 14. Practical Exercise

Create the following structure:

```text
Day-04/
│
├── README.md
├── sample_code.py
└── git_changed_files.py
```

---

## Step 1 – Create the Initial Code

Create `sample_code.py`:

```python
def login(username):
    return username
```

---

## Step 2 – Check Git Status

Run:

```bash
git status
```

Observe whether the file is modified or untracked.

---

## Step 3 – Modify the Code

Change it to:

```python
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
```

---

## Step 4 – View the Diff

Run:

```bash
git diff
```

Observe:

```diff
-    return username
+    query = "SELECT * FROM users WHERE name='" + username + "'"
+    return query
```

---

## Step 5 – Identify Changed Files

Run:

```bash
git diff --name-only
```

Expected output may look like:

```text
Day-04/sample_code.py
```

---

# 15. Python Coding Practice

Create:

```text
git_changed_files.py
```

Add:

```python
import subprocess


result = subprocess.run(
    ["git", "diff", "--name-only"],
    capture_output=True,
    text=True
)


print("Changed files:")
print(result.stdout)
```

Run:

### Windows PowerShell

```powershell
python Day-04\git_changed_files.py
```

Expected behavior:

```text
Changed files:
Day-04/sample_code.py
```

The exact output depends on the files currently modified in the repository.

---

# 16. Improved Coding Practice – Process Changed Files

A slightly more useful version can process each changed file separately:

```python
import subprocess


result = subprocess.run(
    ["git", "diff", "--name-only"],
    capture_output=True,
    text=True
)


changed_files = result.stdout.splitlines()


print("Changed files:")

for file in changed_files:
    print("-", file)
```

This converts Git's output into a Python list and processes each changed file individually.

This is closer to how a future automation pipeline could consume Git information.

---

# 17. Important Difference

There are two different concepts.

### Git Diff

Tells us:

```text
What changed?
```

### Tree-sitter

Tells us:

```text
What is the structure of the code?
```

### Security Scanners

Help determine:

```text
Does the changed code contain a known security issue?
```

Together:

```text
Git Diff
   ↓
Identify Changes
   ↓
Tree-sitter
   ↓
Understand Code Structure
   ↓
Security Scanners
   ↓
Identify Security Findings
```

---

# 18. Connection to Agentic VAPT Stage 1

The Agentic VAPT proposal defines the first major stage as:

## Stage 1 – Detection

The detection layer is deterministic and can include:

* Semgrep
* OSV-Scanner
* Trivy
* Gitleaks
* Checkov
* Tree-sitter

Change scoping provides the input boundary for this stage.

### Simplified Stage 1 Flow

```text
Git Commit
      ↓
Git Diff
      ↓
Identify Changed Files
      ↓
Change Scoping
      ↓
Tree-sitter
      ↓
Security Scanners
      ↓
SARIF Findings
```

The resulting findings can then be passed to the later AI-assisted stages.

---

# 19. Detection → Gate → AI Triage

Change scoping also fits into the larger architecture discussed in the project.

```text
                ┌─────────────────────┐
                │    Git Commit       │
                └──────────┬──────────┘
                           ↓
                ┌─────────────────────┐
                │     Git Diff        │
                └──────────┬──────────┘
                           ↓
                ┌─────────────────────┐
                │  Change Scoping     │
                └──────────┬──────────┘
                           ↓
                ┌─────────────────────┐
                │     Detection       │
                │ Semgrep / Trivy /   │
                │ Gitleaks / etc.     │
                └──────────┬──────────┘
                           ↓
                ┌─────────────────────┐
                │       Gate          │
                └──────────┬──────────┘
                           ↓
                ┌─────────────────────┐
                │     LLM Triage      │
                └──────────┬──────────┘
                           ↓
                ┌─────────────────────┐
                │ Exploit Validation  │
                └──────────┬──────────┘
                           ↓
                ┌─────────────────────┐
                │   Human Review      │
                └─────────────────────┘
```

This demonstrates why change scoping belongs near the beginning of the pipeline.

---

# 20. Why Change Scoping is Important

## Without Change Scoping

```text
Large Repository
      ↓
Scan Everything
      ↓
More Processing
      ↓
More Findings
      ↓
More Noise
      ↓
Higher Analysis Cost
```

## With Change Scoping

```text
Code Change
      ↓
Identify Affected Area
      ↓
Analyze Relevant Code
      ↓
Faster Detection
      ↓
Less Unnecessary Processing
```

The goal is to keep the initial security-analysis path **focused, deterministic, and efficient**.

---

# 21. Change Scoping Does Not Mean "Scan Only the Changed Lines"

This is an important concept.

A vulnerability may depend on code outside the exact changed lines.

For example:

```text
Changed Function
       ↓
Calls Database Function
       ↓
Database Function
       ↓
SQL Query
```

Therefore, a mature VAPT system should consider:

```text
Changed Files
      +
Changed Functions
      +
Relevant Dependencies
      +
Relevant Data Flow
```

This is why change scoping can later be combined with:

* Tree-sitter
* Dependency analysis
* Code graphs
* Data-flow analysis
* Security scanners
* LLM reasoning

The initial scope is narrow, but it can expand when dependencies are relevant.

---

# 22. Relation to the Agentic VAPT Project

The Agentic VAPT project is designed around a pipeline involving:

```text
Source Code
     ↓
Detection
     ↓
Security Findings
     ↓
LLM Analysis
     ↓
Validation
     ↓
Human Review
     ↓
Reporting
```

Day 4 focuses on the **source-code change analysis layer** that happens before deeper security reasoning.

The concept is:

```text
Git
 ↓
Find the Change
 ↓
Scope the Change
 ↓
Understand the Code
 ↓
Detect Security Issues
 ↓
Reason About Findings
```

This prevents the LLM from being unnecessarily exposed to the entire repository when only a small part of the code has changed.

---

# 23. How This Can Help LLM Triage

After deterministic scanners produce findings, the Agentic VAPT system can eventually provide the LLM with relevant context instead of the entire repository.

For example:

```text
Finding
   ↓
Changed File
   ↓
Changed Function
   ↓
Relevant Code
   ↓
Dependency Context
   ↓
LLM Triage
```

The LLM can then reason about questions such as:

```text
Is this finding actually exploitable?
        ↓
Is it a false positive?
        ↓
What data reaches the vulnerable operation?
        ↓
What is the impact?
        ↓
Does the issue require validation?
```

This demonstrates the relationship between deterministic detection and AI-assisted analysis.

---

# 24. Future Extension

The Day 4 implementation is intentionally simple.

A future implementation could evolve from:

```text
git diff --name-only
```

to:

```text
Git Diff
   ↓
Changed Files
   ↓
Changed Lines
   ↓
Changed Functions
   ↓
AST / Tree-sitter
   ↓
Dependency Graph
   ↓
Affected Code
   ↓
Security Scanning
```

Eventually, this information can be represented in a graph:

```text
Commit
  │
  ├── modifies → File
  │                 │
  │                 └── contains → Function
  │                                  │
  │                                  └── calls → Function
  │
  └── introduces → Security Finding
```

This connects the Day 4 concept with the broader **code intelligence and graph-based architecture** of Agentic VAPT.

---

# 25. Day 4 Learning Summary

Today I learned:

* What Git diff is
* How Git identifies code changes
* The meaning of `+` and `-` in a diff
* How to identify changed files
* How to inspect staged and unstaged changes
* What change scoping means
* Why change scoping is important for VAPT
* How to execute Git commands from Python
* How to process Git output using Python
* How Git diff can work together with Tree-sitter
* How changed functions can be identified for security analysis
* Why relevant dependents may also need analysis
* How change scoping connects to Stage 1 Detection
* How change scoping can reduce unnecessary security processing
* How scoped findings can later be passed to LLM triage
* How this concept can evolve into dependency and code-graph analysis

---

# 26. Key Takeaway

The main idea learned today is:

```text
Git tells us:
"What changed?"
```

```text
Tree-sitter tells us:
"What part of the code changed?"
```

```text
Security scanners tell us:
"Is there a potential security issue?"
```

And the Agentic VAPT pipeline brings them together:

```text
Git Commit
     ↓
Git Diff
     ↓
Change Scoping
     ↓
Tree-sitter
     ↓
Relevant Code
     ↓
Security Detection
     ↓
SARIF Findings
     ↓
Gate
     ↓
LLM Triage
     ↓
Exploit Validation
     ↓
Human Review
     ↓
Reporting
```

The goal is not simply to scan code.

The goal is to **understand what changed, determine what is affected, and perform focused security analysis**.

---

# 27. Day 4 Project Relevance

Day 4 focuses on the **change-scoping part of the Agentic VAPT source-analysis pipeline**.

The learning connects directly to the project:

```text
Git Change
    ↓
Changed Files
    ↓
Changed Code
    ↓
Tree-sitter
    ↓
Code Structure
    ↓
Relevant Dependents
    ↓
Security Detection
```

This helps reduce unnecessary analysis while keeping the security pipeline focused on the code affected by a change.

It also provides the foundation for future work involving:

* Automated change detection
* Dependency analysis
* Code graphs
* Security scanner orchestration
* SARIF processing
* LLM-based vulnerability triage
* Exploit validation

---

# 28. Day 4 Deliverables

The expected Day 4 learning/practice output is:

```text
Day-04/
│
├── README.md
├── sample_code.py
└── git_changed_files.py
```

### `sample_code.py`

Contains the original code and a security-relevant modification for practicing Git diff.

### `git_changed_files.py`

Uses Python's `subprocess` module to retrieve changed files from Git.

### `README.md`

Documents:

* Git diff
* Change scoping
* Git + Python
* Git + Tree-sitter
* Real-world application
* Agentic VAPT relevance
* Coding practice
* Day 4 learnings

---

# Status

**Day 4 – In Progress**

## Current Focus

* Git diff
* Changed files
* Changed lines
* Change scoping
* Changed functions
* Git + Python
* Git + Tree-sitter
* Relevant dependents
* Security-analysis workflow
* Agentic VAPT Stage 1 – Detection
* Real-world application of change-aware VAPT

## Next Direction

The next stage can build on this foundation by moving from:

```text
Changed Files
      ↓
Changed Functions
      ↓
Code Structure
```

toward:

```text
Code Structure
      ↓
Security Detection
      ↓
Security Findings
      ↓
AI / LLM Triage
```

This creates a clear progression from **source-code change detection → security detection → intelligent vulnerability analysis**.
