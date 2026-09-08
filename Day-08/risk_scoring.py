def calculate_risk_score(finding):
    """
    Calculate a simple contextual risk score.

    This is a learning model, not a production risk engine.
    """

    severity = finding["severity"].lower()

    score = 0

    # Severity score
    if severity == "high":
        score += 3
    elif severity == "medium":
        score += 2
    elif severity == "low":
        score += 1

    context = finding.get("context", {})

    # Contextual signals
    if context.get("user_input"):
        score += 2

    if context.get("database_operation"):
        score += 2

    if context.get("authentication"):
        score += 2

    if context.get("command_execution"):
        score += 3

    if context.get("external_endpoint"):
        score += 2

    if context.get("sensitive_data"):
        score += 2

    return score


def determine_priority(score):
    """Convert risk score into a priority category."""

    if score >= 8:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    return "LOW"