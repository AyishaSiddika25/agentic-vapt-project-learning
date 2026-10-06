import json

from validate_llm_output import load_results, validate_result


def determine_security_decision(result):
    """
    Determine the next security action based on
    validation status and LLM confidence.
    """

    errors = validate_result(result)

    if errors:
        return "INVALID_OUTPUT"

    confidence = result["confidence"]

    if confidence == "High":
        return "NEEDS_VALIDATION"

    if confidence == "Medium":
        return "NEEDS_REVIEW"

    return "INSUFFICIENT_EVIDENCE"


def main():

    results = load_results(
        "Day-12/sample_llm_results.json"
    )

    print("Day 12 – Security Decision Layer\n")

    for index, result in enumerate(results, start=1):

        decision = determine_security_decision(result)

        print("=" * 60)
        print(f"Result {index}")
        print(f"Finding: {result['finding']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Decision: {decision}")
        print()


if __name__ == "__main__":
    main()