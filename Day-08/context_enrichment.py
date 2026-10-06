import json


def load_findings(file_path):
    """Load normalized security findings from JSON."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def enrich_finding(finding):
    """
    Add security-related context indicators to a finding.

    These indicators are signals for prioritization.
    They do not prove exploitability.
    """

    text = (
        finding["rule_id"]
        + " "
        + finding["message"]
        + " "
        + finding["file"]
    ).lower()

    context = {
        "user_input": False,
        "database_operation": False,
        "authentication": False,
        "command_execution": False,
        "external_endpoint": False,
        "sensitive_data": False
    }

    if any(keyword in text for keyword in [
        "input",
        "request",
        "parameter",
        "user"
    ]):
        context["user_input"] = True

    if any(keyword in text for keyword in [
        "sql",
        "query",
        "database",
        "execute"
    ]):
        context["database_operation"] = True

    if any(keyword in text for keyword in [
        "login",
        "password",
        "authentication",
        "token",
        "session"
    ]):
        context["authentication"] = True

    if any(keyword in text for keyword in [
        "command",
        "shell",
        "subprocess",
        "os.system",
        "exec"
    ]):
        context["command_execution"] = True

    if any(keyword in text for keyword in [
        "api",
        "endpoint",
        "request"
    ]):
        context["external_endpoint"] = True

    if any(keyword in text for keyword in [
        "password",
        "secret",
        "credential",
        "token"
    ]):
        context["sensitive_data"] = True

    finding["context"] = context

    return finding


def main():
    findings = load_findings(
        "Day-08/sample_findings.json"
    )

    print("Finding Context Enrichment:\n")

    for finding in findings:
        enriched = enrich_finding(finding)

        print(
            f"{enriched['rule_id']} | "
            f"{enriched['file']}:{enriched['start_line']}"
        )

        print("Context:")

        for key, value in enriched["context"].items():
            print(f"  {key}: {value}")

        print()


if __name__ == "__main__":
    main()