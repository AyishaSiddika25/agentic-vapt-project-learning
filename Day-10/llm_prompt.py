def build_security_analysis_prompt(finding, source_context):
    """
    Build a security-analysis prompt containing
    finding metadata, security context, and source code.
    """

    context = finding.get("context", {})

    source_code = "\n".join(
        f"{line['line_number']}: {line['code']}"
        for line in source_context
    )

    prompt = f"""
You are a cybersecurity analysis assistant.

Analyze the following security finding using the
available finding metadata, security context, and
relevant source code.

Finding:
{finding["message"]}

Rule ID:
{finding["rule_id"]}

Scanner:
{finding["scanner"]}

Severity:
{finding["severity"]}

File:
{finding["file"]}

Location:
Lines {finding["start_line"]}-{finding["end_line"]}

Risk Score:
{finding.get("risk_score", "Not available")}

Priority:
{finding.get("priority", "Not available")}

Security Context:
- User Input: {context.get("user_input", False)}
- Database Operation: {context.get("database_operation", False)}
- Authentication: {context.get("authentication", False)}
- Command Execution: {context.get("command_execution", False)}
- External Endpoint: {context.get("external_endpoint", False)}
- Sensitive Data: {context.get("sensitive_data", False)}

Relevant Source Code:
{source_code}

Provide your analysis using these sections:

1. Security Reasoning
2. Evidence
3. Confidence
4. Recommended Next Step

Use the source code as evidence.

Do not claim that the vulnerability is confirmed
unless sufficient evidence is available.
"""

    return prompt


if __name__ == "__main__":

    sample_finding = {
        "message": "Possible SQL injection",
        "rule_id": "python.sql-injection",
        "scanner": "Semgrep",
        "severity": "high",
        "file": "Day-10/login.py",
        "start_line": 4,
        "end_line": 4,
        "risk_score": 7,
        "priority": "MEDIUM",
        "context": {
            "user_input": True,
            "database_operation": True,
            "authentication": True,
            "command_execution": False,
            "external_endpoint": False,
            "sensitive_data": False
        }
    }

    sample_source_context = [
        {
            "line_number": 2,
            "code": "    query = \"SELECT * FROM users WHERE username='\" + username + \"'\""
        },
        {
            "line_number": 3,
            "code": "    return query"
        }
    ]

    print(
        build_security_analysis_prompt(
            sample_finding,
            sample_source_context
        )
    )