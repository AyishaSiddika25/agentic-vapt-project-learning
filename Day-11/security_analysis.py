import json

from llm_client import build_llm_request


def analyze_finding(finding):
    """
    Simulate a structured LLM security-analysis response.

    This learning implementation does not call an external
    LLM API. It demonstrates the expected structure of the
    model's security reasoning output.
    """

    context = finding.get("context", {})
    source_context = finding.get("source_context", [])

    evidence = []

    if context.get("user_input"):
        evidence.append(
            "User-controlled input is involved."
        )

    if context.get("database_operation"):
        evidence.append(
            "A database operation is involved."
        )

    if context.get("authentication"):
        evidence.append(
            "The finding is related to authentication."
        )

    if context.get("command_execution"):
        evidence.append(
            "Command execution is involved."
        )

    if context.get("sensitive_data"):
        evidence.append(
            "Sensitive data may be involved."
        )

    if source_context:
        evidence.append(
            "Relevant source-code evidence is available."
        )

    if not evidence:
        evidence.append(
            "Insufficient contextual evidence is available."
        )

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
            "the scanner result, security context, and "
            "available source-code evidence."
        ),
        "evidence": evidence,
        "confidence": confidence,
        "recommended_next_step": (
            "Validate the suspected security path using "
            "source-code analysis and security testing before "
            "treating the finding as confirmed."
        )
    }


def main():

    with open(
        "Day-11/sample_findings.json",
        "r",
        encoding="utf-8"
    ) as file:
        findings = json.load(file)

    results = []

    print("Day 11 – LLM Security Analysis\n")

    for finding in findings:

        print("=" * 60)

        print(
            f"Finding: {finding['rule_id']} | "
            f"{finding['file']}:{finding['start_line']}"
        )

        # Prepare the structured request that would be
        # provided to an LLM.
        request = build_llm_request(finding)

        print("\nLLM Request Prepared:")
        print(
            json.dumps(
                request,
                indent=4
            )
        )

        # Simulate the structured response expected
        # from the LLM.
        analysis = analyze_finding(finding)

        result = {
            "finding": finding,
            "llm_analysis": analysis
        }

        results.append(result)

        print("\nSecurity Analysis Result:")
        print(
            json.dumps(
                analysis,
                indent=4
            )
        )

    # Save structured results for the next stage.
    with open(
        "Day-11/results.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            results,
            file,
            indent=4
        )

    print("\nResults saved to Day-11/results.json")


if __name__ == "__main__":
    main()