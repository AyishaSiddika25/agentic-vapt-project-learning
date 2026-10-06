import json


def load_findings(file_path):
    """Load security findings from JSON."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def extract_source_context(file_path, start_line, end_line, context_lines=2):
    """
    Extract source code around the finding location.

    A small number of lines before and after the finding
    are included to provide useful context.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    start_index = max(0, start_line - 1 - context_lines)
    end_index = min(len(lines), end_line + context_lines)

    context = []

    for index in range(start_index, end_index):
        context.append({
            "line_number": index + 1,
            "code": lines[index].rstrip("\n")
        })

    return context


def main():
    findings = load_findings(
        "Day-10/sample_findings.json"
    )

    print("Day 10 – Source Code Context Extraction\n")

    for finding in findings:

        print("=" * 60)

        print(
            f"Finding: {finding['rule_id']} | "
            f"{finding['file']}:{finding['start_line']}"
        )

        context = extract_source_context(
            finding["file"],
            finding["start_line"],
            finding["end_line"]
        )

        print("\nRelevant Source Code:\n")

        for line in context:
            print(
                f"{line['line_number']:>3}: "
                f"{line['code']}"
            )

        print()


if __name__ == "__main__":
    main()