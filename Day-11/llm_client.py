import json


def build_llm_request(finding):
    """
    Prepare a structured request for an LLM security analysis.

    This function prepares the information that would be
    sent to an LLM client. It does not make an API call.
    """

    context = finding.get("context", {})
    source_context = finding.get("source_context", [])

    source_code = "\n".join(
        f"{line['line_number']}: {line['code']}"
        for line in source_context
    )

    request = {
        "system_message": (
            "You are a cybersecurity analysis assistant. "
            "Analyze security findings using evidence from "
            "the scanner result and source code."
        ),
        "finding": {
            "scanner": finding["scanner"],
            "rule_id": finding["rule_id"],
            "message": finding["message"],
            "severity": finding["severity"],
            "file": finding["file"],
            "location": {
                "start_line": finding["start_line"],
                "end_line": finding["end_line"]
            }
        },
        "risk": {
            "risk_score": finding.get("risk_score"),
            "priority": finding.get("priority")
        },
        "security_context": context,
        "source_code": source_code,
        "requested_output": [
            "security_reasoning",
            "evidence",
            "confidence",
            "recommended_next_step"
        ]
    }

    return request


def main():
    with open(
        "Day-11/sample_findings.json",
        "r",
        encoding="utf-8"
    ) as file:
        findings = json.load(file)

    print("Day 11 – LLM Client Request Preparation\n")

    for finding in findings:

        request = build_llm_request(finding)

        print("=" * 60)
        print(
            f"Finding: {finding['rule_id']} | "
            f"{finding['file']}:{finding['start_line']}"
        )

        print("\nStructured LLM Request:\n")

        print(
            json.dumps(
                request,
                indent=4
            )
        )

        print()


if __name__ == "__main__":
    main()