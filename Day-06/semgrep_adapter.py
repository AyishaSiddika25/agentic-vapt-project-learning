import json
import hashlib
import subprocess
from pathlib import Path


def generate_fingerprint(
    rule_id: str,
    file_path: str,
    start_line: int | None,
    end_line: int | None,
) -> str:
    """Generate a deterministic fingerprint for a finding."""

    normalized_path = file_path.replace("\\", "/")

    fingerprint_input = (
        f"{rule_id}|"
        f"{normalized_path}|"
        f"{start_line}|"
        f"{end_line}"
    )

    return hashlib.sha256(
        fingerprint_input.encode("utf-8")
    ).hexdigest()


def run_semgrep(
    rule_file: str,
    target: str,
    output_file: str,
) -> str:
    """Run Semgrep and generate SARIF output."""

    command = [
        "semgrep",
        "--config",
        rule_file,
        target,
        "--sarif",
        "-o",
        output_file,
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

    # Semgrep can return 1 when findings are detected.
    # Therefore, 0 and 1 are treated as successful execution.
    if result.returncode not in (0, 1):
        return "EXECUTION_ERROR"

    return "SUCCESS"


def load_sarif(file_path: str) -> dict:
    """Load a SARIF file and return it as a Python dictionary."""

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except (
        FileNotFoundError,
        json.JSONDecodeError,
    ):
        return {}


def normalize_findings(
    sarif_data: dict
) -> list[dict]:
    """Convert SARIF results into a normalized finding format."""

    findings = []

    for run in sarif_data.get(
        "runs",
        []
    ):

        rule_severity = {}

        tool = run.get(
            "tool",
            {}
        )

        driver = tool.get(
            "driver",
            {}
        )

        # Extract severity from SARIF rule definitions
        for rule in driver.get(
            "rules",
            []
        ):

            rule_id = rule.get(
                "id",
                ""
            )

            default_config = rule.get(
                "defaultConfiguration",
                {}
            )

            severity = default_config.get(
                "level",
                "warning"
            )

            rule_severity[rule_id] = severity

        # Extract individual findings
        for result in run.get(
            "results",
            []
        ):

            locations = result.get(
                "locations",
                []
            )

            if not locations:
                continue

            physical_location = locations[0].get(
                "physicalLocation",
                {}
            )

            artifact = physical_location.get(
                "artifactLocation",
                {}
            )

            region = physical_location.get(
                "region",
                {}
            )

            rule_id = result.get(
                "ruleId",
                ""
            )

            file_path = artifact.get(
                "uri",
                ""
            )

            start_line = region.get(
                "startLine"
            )

            start_column = region.get(
                "startColumn"
            )

            end_line = region.get(
                "endLine"
            )

            end_column = region.get(
                "endColumn"
            )

            fingerprint = generate_fingerprint(
                rule_id,
                file_path,
                start_line,
                end_line,
            )

            finding = {
                "scanner": "Semgrep",
                "rule_id": rule_id,
                "message": result.get(
                    "message",
                    {}
                ).get(
                    "text",
                    ""
                ),
                "severity": rule_severity.get(
                    rule_id,
                    "warning"
                ),
                "file": file_path,
                "start_line": start_line,
                "start_column": start_column,
                "end_line": end_line,
                "end_column": end_column,
                "fingerprint": fingerprint,
            }

            findings.append(finding)

    return findings


def determine_scan_status(
    sarif_data: dict,
    findings: list[dict],
    execution_status: str,
) -> str:
    """Determine the final scanner status."""

    if execution_status == "TIMEOUT":
        return "TIMEOUT"

    if execution_status == "EXECUTION_ERROR":
        return "EXECUTION_ERROR"

    if not isinstance(
        sarif_data,
        dict
    ):
        return "INVALID_OUTPUT"

    if sarif_data.get(
        "version"
    ) != "2.1.0":
        return "INVALID_OUTPUT"

    if "runs" not in sarif_data:
        return "INVALID_OUTPUT"

    if findings:
        return "FINDINGS"

    return "NO_FINDINGS"


def main() -> None:

    rule_file = (
        "Day-06/semgrep_rules/sql-injection.yml"
    )

    target = (
        "Day-06/semgrep_demo.py"
    )

    output_file = (
        "Day-06/semgrep_results.sarif"
    )

    print("========================================")
    print("Semgrep Finding Adapter")
    print("========================================")

    print("\nRunning Semgrep...")

    execution_status = run_semgrep(
        rule_file,
        target,
        output_file,
    )

    print(
        f"Semgrep Execution : "
        f"{execution_status}"
    )

    sarif_data = load_sarif(
        output_file
    )

    findings = normalize_findings(
        sarif_data
    )

    status = determine_scan_status(
        sarif_data,
        findings,
        execution_status,
    )

    print(
        f"Scan Status       : "
        f"{status}"
    )

    if not findings:
        print(
            "\nNo findings detected."
        )
        return

    print(
        f"\nNormalized Findings: "
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
            f"Scanner      : "
            f"{finding['scanner']}"
        )

        print(
            f"Rule ID      : "
            f"{finding['rule_id']}"
        )

        print(
            f"Message      : "
            f"{finding['message']}"
        )

        print(
            f"Severity     : "
            f"{finding['severity']}"
        )

        print(
            f"File         : "
            f"{finding['file']}"
        )

        print(
            f"Location     : "
            f"{finding['start_line']}:"
            f"{finding['start_column']} - "
            f"{finding['end_line']}:"
            f"{finding['end_column']}"
        )

        print(
            f"Fingerprint  : "
            f"{finding['fingerprint']}"
        )


if __name__ == "__main__":
    main()