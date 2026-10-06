def build_security_analysis_prompt(finding):
    """
    Build a structured prompt for LLM-based security analysis.
    """

    context = finding.get("context", {})

    prompt = f"""
You are a cybersecurity analysis assistant.

Analyze the following security finding and explain why it
may or may not represent a real security issue.

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

Provide your analysis using these sections:

1. Security Reasoning
2. Evidence
3. Confidence
4. Recommended Next Step

Do not claim that the vulnerability is confirmed unless
sufficient evidence is available.
"""

    return prompt


if __name__ == "__main__":
    sample_finding = {
        "scanner": "Semgrep",
        "rule_id": "python.sql-injection",
        "message": "Possible SQL injection",
        "severity": "high",
        "file": "login.py",
        "start_line": 10,
        "end_line": 10,
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

    print(build_security_analysis_prompt(sample_finding))