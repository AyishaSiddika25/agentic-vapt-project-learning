import subprocess
from pathlib import Path

from semgrep_adapter import (
    load_sarif,
    normalize_findings,
    determine_scan_status,
)


RULE_FILE = "Day-06/semgrep_rules/sql-injection.yml"
OUTPUT_FILE = "Day-06/semgrep_results.sarif"


def get_changed_python_files():
    """Get Python files changed in the latest Git commit."""

    try:
        result = subprocess.run(
            [
                "git",
                "diff",
                "--name-only",
                "HEAD~1",
                "HEAD",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    except Exception:
        return []

    if result.returncode != 0:
        return []

    changed_files = []

    for file in result.stdout.splitlines():

        file = file.strip()

        if file.endswith(".py"):
            changed_files.append(file)

    return changed_files


def filter_existing_files(files):
    """Keep only files that currently exist."""

    existing_files = []

    for file in files:

        if Path(file).exists():
            existing_files.append(file)

    return existing_files


def run_semgrep_on_files(files):
    """Run Semgrep against changed Python files."""

    if not files:
        return "NO_TARGETS"

    command = [
        "semgrep",
        "--config",
        RULE_FILE,
        *files,
        "--sarif",
        "-o",
        OUTPUT_FILE,
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    except subprocess.TimeoutExpired:
        return "TIMEOUT"

    except FileNotFoundError:
        return "EXECUTION_ERROR"

    except Exception:
        return "EXECUTION_ERROR"

    # Semgrep may return 1 when findings are detected.
    if result.returncode in (0, 1):
        return "SUCCESS"

    return "EXECUTION_ERROR"


def main():

    print("========================================")
    print("Differential Semgrep Analysis")
    print("========================================")

    print("\nChecking Git changes...")

    changed_files = get_changed_python_files()

    print(
        f"Changed Python Files : "
        f"{len(changed_files)}"
    )

    for file in changed_files:
        print(f"  - {file}")

    existing_files = filter_existing_files(
        changed_files
    )

    if not existing_files:

        print(
            "\nNo existing changed Python files "
            "were found."
        )

        return

    print(
        "\nRunning Semgrep only on "
        "changed Python files..."
    )

    execution_status = run_semgrep_on_files(
        existing_files
    )

    print(
        f"Semgrep Execution : "
        f"{execution_status}"
    )

    if execution_status != "SUCCESS":

        print(
            f"Scan Status : "
            f"{execution_status}"
        )

        return

    sarif_data = load_sarif(
        OUTPUT_FILE
    )

    findings = normalize_findings(
        sarif_data
    )

    scan_status = determine_scan_status(
        sarif_data,
        findings,
        execution_status,
    )

    print(
        f"Scan Status : "
        f"{scan_status}"
    )

    print(
        f"\nNormalized Findings : "
        f"{len(findings)}"
    )

    for index, finding in enumerate(
        findings,
        start=1
    ):

        print(
            f"\nFinding {index}"
        )

        print(
            f"Scanner     : "
            f"{finding['scanner']}"
        )

        print(
            f"Rule ID     : "
            f"{finding['rule_id']}"
        )

        print(
            f"Message     : "
            f"{finding['message']}"
        )

        print(
            f"Severity    : "
            f"{finding['severity']}"
        )

        print(
            f"File        : "
            f"{finding['file']}"
        )

        print(
            f"Location    : "
            f"{finding['start_line']}:"
            f"{finding['start_column']} - "
            f"{finding['end_line']}:"
            f"{finding['end_column']}"
        )

        print(
            f"Fingerprint : "
            f"{finding['fingerprint']}"
        )


if __name__ == "__main__":
    main()