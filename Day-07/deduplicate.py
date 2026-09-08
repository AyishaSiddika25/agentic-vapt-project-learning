import json

from fingerprint import create_fingerprint


def load_findings(file_path):
    """Load normalized findings from a JSON file."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def deduplicate_findings(findings):
    """
    Generate fingerprints and remove duplicate findings.

    The first occurrence of each fingerprint is retained.
    """

    unique_findings = {}
    duplicates = []

    for finding in findings:
        fingerprint = create_fingerprint(finding)

        finding["fingerprint"] = fingerprint

        if fingerprint in unique_findings:
            duplicates.append(finding)
        else:
            unique_findings[fingerprint] = finding

    return list(unique_findings.values()), duplicates


def main():
    findings = load_findings(
        "Day-07/sample_findings.json"
    )

    unique_findings, duplicates = deduplicate_findings(
        findings
    )

    print("Total findings:", len(findings))
    print("Unique findings:", len(unique_findings))
    print("Duplicates:", len(duplicates))

    print("\nUnique Findings:")

    for finding in unique_findings:
        print(
            f"- {finding['rule_id']} "
            f"{finding['file']}:{finding['start_line']}-"
            f"{finding['end_line']}"
        )
        print(
            f"  Fingerprint: {finding['fingerprint']}"
        )


if __name__ == "__main__":
    main()