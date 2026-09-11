import json


REQUIRED_FIELDS = [
    "finding",
    "security_reasoning",
    "evidence",
    "confidence",
    "recommended_next_step"
]


def load_results(file_path):
    """Load structured LLM results from JSON."""

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def validate_result(result):
    """
    Validate the structure of an LLM security-analysis result.
    """

    errors = []

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in result:
            errors.append(
                f"Missing required field: {field}"
            )

    # Validate evidence
    if "evidence" in result:
        if not isinstance(result["evidence"], list):
            errors.append(
                "Evidence must be a list."
            )

    # Validate confidence
    if "confidence" in result:
        allowed_confidence = [
            "High",
            "Medium",
            "Low"
        ]

        if result["confidence"] not in allowed_confidence:
            errors.append(
                "Invalid confidence value."
            )

    return errors


def main():

    results = load_results(
        "Day-12/sample_llm_results.json"
    )

    print("Day 12 – LLM Output Validation\n")

    for index, result in enumerate(results, start=1):

        errors = validate_result(result)

        print("=" * 60)
        print(f"Result {index}")
        print(f"Finding: {result.get('finding', 'Unknown')}")

        if errors:
            print("Status: INVALID")

            for error in errors:
                print(f"- {error}")

        else:
            print("Status: VALID")

        print()


if __name__ == "__main__":
    main()