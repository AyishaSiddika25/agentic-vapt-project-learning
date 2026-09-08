import json

from source_context import load_findings, extract_source_context
from llm_prompt import build_security_analysis_prompt


def main():
    findings = load_findings(
        "Day-10/sample_findings.json"
    )

    print("Day 10 – End-to-End Security Context Analysis\n")

    for finding in findings:

        print("=" * 60)

        print(
            f"Finding: {finding['rule_id']} | "
            f"{finding['file']}:{finding['start_line']}"
        )

        # Extract source code around the finding
        source_context = extract_source_context(
            finding["file"],
            finding["start_line"],
            finding["end_line"]
        )

        # Build the AI-ready security prompt
        prompt = build_security_analysis_prompt(
            finding,
            source_context
        )

        print("\nAI-Ready Security Analysis Prompt:\n")
        print(prompt)


if __name__ == "__main__":
    main()