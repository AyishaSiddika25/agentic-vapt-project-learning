from context_enrichment import (
    load_findings,
    enrich_finding
)

from risk_scoring import (
    calculate_risk_score,
    determine_priority
)


def triage_finding(finding):
    """
    Enrich a finding, calculate its risk score,
    and assign a priority.
    """

    finding = enrich_finding(finding)

    score = calculate_risk_score(finding)

    priority = determine_priority(score)

    finding["risk_score"] = score
    finding["priority"] = priority

    return finding


def main():
    findings = load_findings(
        "Day-08/sample_findings.json"
    )

    print("Day 8 – Risk-Aware Finding Triage\n")

    for finding in findings:
        result = triage_finding(finding)

        print(
            f"{result['rule_id']} | "
            f"{result['file']}:{result['start_line']}"
        )

        print(f"Severity: {result['severity']}")
        print(f"Risk Score: {result['risk_score']}")
        print(f"Priority: {result['priority']}")

        print("Context:")

        for key, value in result["context"].items():
            if value:
                print(f"  - {key}")

        print("-" * 50)


if __name__ == "__main__":
    main()