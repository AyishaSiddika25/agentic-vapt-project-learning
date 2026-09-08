import json

from llm_prompt import build_security_analysis_prompt


def load_findings(file_path):
    """Load security findings from a JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def analyze_finding(finding):
    """
    Simulate the structured result that an LLM
    could produce after analyzing a security finding.
    """

    context = finding.get("context", {})

    evidence = []

    if context.get("user_input"):
        evidence.append("User-controlled input is involved.")

    if context.get("database_operation"):
        evidence.append("A database operation is involved.")

    if context.get("authentication"):
        evidence.append("The finding is related to authentication.")

    if context.get("command_execution"):
        evidence.append("Command execution is involved.")

    if context.get("external_endpoint"):
        evidence.append("An external endpoint is involved.")

    if context.get("sensitive_data"):
        evidence.append("Sensitive data may be involved.")

    if not evidence:
        evidence.append("Insufficient contextual evidence is available.")

    if finding["severity"].lower() == "high":
        confidence = "High"
    elif finding["severity"].lower() == "medium":
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "finding": finding["message"],
        "security_reasoning": (
            "The finding appears security-relevant based on "
            "the available scanner result and security context."
        ),
        "evidence": evidence,
        "confidence": confidence,
        "recommended_next_step": (
            "Review the relevant source code and validate "
            "whether the suspected security path is actually reachable."
        )
    }


def main():
    findings = load_findings(
        "Day-09/sample_findings.json"
    )

    print("Day 9 – LLM-Based Security Finding Analysis\n")

    for finding in findings:

        print("=" * 60)

        print(
            f"Finding: {finding['rule_id']} | "
            f"{finding['file']}:{finding['start_line']}"
        )

        print("\nGenerated LLM Prompt:")
        print(build_security_analysis_prompt(finding))

        analysis = analyze_finding(finding)

        print("\nStructured Security Analysis:")
        print(
            json.dumps(
                analysis,
                indent=4
            )
        )

        print()


if __name__ == "__main__":
    main()