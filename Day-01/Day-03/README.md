# **Day 3 – Source Code Parsing & Tree-sitter**

## **Objective**

Today I learned how source code can be parsed into a structured representation using Tree-sitter.

This is an important step in the Agentic VAPT project because the system needs to understand the structure and relationships within source code before performing deeper security analysis.

---

## **1. What is Source Code Parsing?**

Source code parsing is the process of analyzing source code and converting it into a structured representation that a program can understand.

For example:

```python
def login(username):
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return query
```

Instead of treating the code as plain text, a parser identifies structures such as:

* Functions
* Parameters
* Variables
* Assignments
* Function calls
* Expressions
* Return statements

This structured representation can then be used for further code and security analysis.

---

## **2. What is Tree-sitter?**

Tree-sitter is a parser system that can parse source code and generate a syntax tree.

It supports multiple programming languages, making it useful for a project such as Agentic VAPT where the application may contain different types of source code.

**Basic flow:**

```text
Source Code
     ↓
Tree-sitter Parser
     ↓
Syntax Tree
     ↓
Structured Code Representation
     ↓
Security Analysis
```

---

## **3. Why Tree-sitter is Useful for Agentic VAPT**

The Agentic VAPT system needs to understand source-code structure instead of relying only on text-based searches.

For example:

```python
username = request.args.get("username")

query = "SELECT * FROM users WHERE name='" + username + "'"
```

A security analysis system should be able to understand the relationship between:

```text
User Input
    ↓
username
    ↓
String Concatenation
    ↓
SQL Query
```

Tree-sitter provides the syntax structure that can be used as a foundation for this type of analysis.

---

## **4. Tree-sitter vs Python AST**

On Day 2, I learned about Python's built-in `ast` module.

Today I learned how Tree-sitter provides another approach to source-code parsing.

**Python AST**

```text
Python Source Code
        ↓
Python AST
        ↓
Python-specific Code Structure
```

**Tree-sitter**

```text
Source Code
     ↓
Tree-sitter
     ↓
Syntax Tree
```

Tree-sitter is particularly useful for a multi-language security-analysis system because it provides parsers for many programming languages.

---

## **5. Connection with AST and CPG**

Tree-sitter is part of the source-analysis foundation of the project.

The planned progression is:

```text
Source Code
     ↓
Tree-sitter Parsing
     ↓
Syntax Tree
     ↓
Code Structure
     ↓
AST / CPG
     ↓
Security Analysis
     ↓
AI Analysis
```

A Code Property Graph (CPG) can later represent relationships such as:

* Abstract syntax relationships
* Data flow
* Control flow

This can help the Agentic VAPT system identify potentially dangerous paths in source code.

---

## **6. Practical Implementation**

### **Installation**

The Tree-sitter packages were installed using:

```bash
pip install tree-sitter tree-sitter-python
```

### **Files Created**

```text
Day-03/
│
├── README.md
├── sample_code.py
├── treesitter_demo.py
└── treesitter_walk.py
```

---

## **7. Sample Source Code**

Example source code used for parsing:

```python
from flask import request

def login():
    username = request.args.get("username")

    query = "SELECT * FROM users WHERE name='" + username + "'"

    return query
```

This example contains a user-controlled input and SQL query construction so that the code structure can later be studied from a security-analysis perspective.

---

## **8. Tree-sitter Parsing**

A Tree-sitter parser can read the source file and generate a syntax tree.

### **Example Implementation**

```python
from tree_sitter import Language, Parser
import tree_sitter_python as tspython


PY_LANGUAGE = Language(tspython.language())

parser = Parser(PY_LANGUAGE)


with open("sample_code.py", "r", encoding="utf-8") as file:
    source_code = file.read()


tree = parser.parse(source_code.encode("utf-8"))


print("Tree-sitter Syntax Tree:")
print(tree.root_node)
```

The output represents the source code as a hierarchy of syntax nodes.

---

## **9. Walking Through the Syntax Tree**

The syntax tree can also be traversed to inspect individual nodes.

For example:

```text
module
 ├── import_statement
 ├── function_definition
 │    ├── identifier
 │    ├── parameters
 │    └── block
 │         ├── assignment
 │         └── return_statement
```

This makes it possible to inspect specific parts of the source code programmatically.

---

## **10. Security Analysis Connection**

Tree-sitter itself does not detect vulnerabilities.

Its role is to provide structured information about the source code.

The overall process can later become:

```text
Source Code
     ↓
Tree-sitter
     ↓
Syntax Tree
     ↓
Data / Control Relationships
     ↓
Security Rules
     ↓
Potential Vulnerability
     ↓
AI Analysis
     ↓
Validation
```

For example, the system could eventually analyze a pattern such as:

```text
Request Input
     ↓
Variable
     ↓
String Concatenation
     ↓
SQL Query
```

and use this information as part of SQL Injection analysis.

---

## **11. Key Learnings**

Today I learned:

* What source-code parsing means.
* Why structured source-code representation is useful in VAPT.
* What Tree-sitter is.
* How Tree-sitter generates a syntax tree.
* How syntax-tree nodes represent different parts of source code.
* The difference between Python AST and Tree-sitter.
* How source parsing can become a foundation for AST/CPG generation.
* How structured code information can later support security analysis and AI reasoning.

---

## **12. Day 3 Project Relevance**

Day 3 focuses on the Source Code Analysis layer of the Agentic VAPT architecture.

```text
Git Repository
      ↓
Git Commit / Diff
      ↓
Source Code Analysis
      ↓
Tree-sitter
      ↓
AST / CPG
      ↓
Security Testing
      ↓
AI Analysis
      ↓
Finding Validation
      ↓
Risk / Attack Path
      ↓
VAPT Report
```

The main goal is to understand how the Agentic VAPT system can move from raw source code to a structured representation that can later be analyzed for security vulnerabilities.

---

## **13. Day 3 Workflow**

```text
1. Create Day-03 folder
        ↓
2. Create sample_code.py
        ↓
3. Install Tree-sitter
        ↓
4. Create treesitter_demo.py
        ↓
5. Run the parser
        ↓
6. Create treesitter_walk.py
        ↓
7. Run the tree traversal
        ↓
8. Analyze the syntax-tree output
        ↓
9. Document the learning
        ↓
10. Commit the Day-3 work
        ↓
11. Push to GitHub
```

---

## **14. Day 3 Status**

**Status:** In Progress

### **Current Focus**

* Source-code parsing
* Tree-sitter
* Syntax trees
* AST/CPG foundation
* Security-analysis use cases

---

## **15. Day 3 Goal**

The main goal of Day 3 is to understand how the Agentic VAPT system can take raw source code and convert it into a structured representation that can later support:

* Security analysis
* CPG generation
* Vulnerability detection
* AI-based reasoning

---

## **Summary**

Day 3 builds the foundation for **source-code intelligence** in the Agentic VAPT project.

The key concept is:

```text
Raw Source Code
       ↓
Tree-sitter Parser
       ↓
Syntax Tree
       ↓
Structured Code
       ↓
Security Analysis
       ↓
AI Reasoning
```

This learning will be used in the later stages of the project for AST/CPG generation, vulnerability analysis, validation, and AI-assisted VAPT.
