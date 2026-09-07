import json
from fingerprint import create_fingerprint


with open("Day-07/sample_findings.json", "r", encoding="utf-8") as file:
    findings = json.load(file)


# Add fingerprints
for finding in findings:
    finding["fingerprint"] = create_fingerprint(finding)


# Remove duplicates
unique_findings = {}

for finding in findings:
    fingerprint = finding["fingerprint"]

    if fingerprint not in unique_findings:
        unique_findings[fingerprint] = finding


# Apply initial gating
print("Initial Gate Results:\n")

for finding in unique_findings.values():

    severity = finding["severity"]

    if severity in ["high", "medium"]:
        decision = "KEEP"
    else:
        decision = "FILTER"

    print(
        f"{finding['rule_id']} | "
        f"{finding['file']}:{finding['line']} | "
        f"{severity} | "
        f"{decision}"
    )