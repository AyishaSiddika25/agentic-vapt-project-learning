import json
from fingerprint import create_fingerprint


with open("Day-07/sample_findings.json", "r", encoding="utf-8") as file:
    findings = json.load(file)


unique_findings = {}
duplicates = []


for finding in findings:
    fingerprint = create_fingerprint(finding)
    finding["fingerprint"] = fingerprint

    if fingerprint in unique_findings:
        duplicates.append(finding)
    else:
        unique_findings[fingerprint] = finding


print("Total findings:", len(findings))
print("Unique findings:", len(unique_findings))
print("Duplicates:", len(duplicates))


print("\nUnique Findings:")

for finding in unique_findings.values():
    print(
        f"- {finding['rule_id']} "
        f"{finding['file']}:{finding['line']}"
    )