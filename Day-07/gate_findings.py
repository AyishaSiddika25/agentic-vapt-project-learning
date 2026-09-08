import json

from deduplicate import deduplicate_findings


def load_findings(file_path):
    """Load normalized findings from a JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def determine_gate_decision(finding):
    """
    Apply the Day-7 initial severity-based gate.

    Policy:
        high   -> KEEP
        medium -> KEEP
        other  -> FILTER
    """

    severity = finding["severity"].lower()

    if severity in ["high", "medium"]:
        return "KEEP"

    return "FILTER"


def main():
    findings = load_findings(
        "Day-07/sample_findings.json"
    )

    unique_findings, duplicates = deduplicate_findings(
        findings
    )

    print("Initial Gate Results:\n")

    print("Total findings:", len(findings))
    print("Unique findings:", len(unique_findings))
    print("Duplicates removed:", len(duplicates))

    print()

    for finding in unique_findings:
        decision = determine_gate_decision(finding)

        print(
            f"{finding['rule_id']} | "
            f"{finding['file']}:{finding['start_line']}-"
            f"{finding['end_line']} | "
            f"{finding['severity']} | "
            f"{decision}"
        )


if __name__ == "__main__":
    main()