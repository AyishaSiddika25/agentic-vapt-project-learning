import subprocess
import ast


def get_changed_files():
    result = subprocess.run(
        ["git", "diff", "--name-only"],
        capture_output=True,
        text=True,
        check=True
    )

    files = result.stdout.strip().splitlines()

    python_files = [
        file for file in files
        if file.endswith(".py")
    ]

    return python_files


def get_changed_line_numbers(file_path):
    result = subprocess.run(
        ["git", "diff", "--unified=0", "--", file_path],
        capture_output=True,
        text=True,
        check=True
    )

    changed_lines = []

    for line in result.stdout.splitlines():

        if line.startswith("@@"):
            new_part = line.split("+")[1].split(" ")[0]

            if "," in new_part:
                start, count = new_part.split(",")
                start = int(start)
                count = int(count)
            else:
                start = int(new_part)
                count = 1

            for number in range(start, start + count):
                changed_lines.append(number)

    return changed_lines


def find_affected_functions(file_path, changed_lines):

    with open(file_path, "r", encoding="utf-8") as file:
        source_code = file.read()

    tree = ast.parse(source_code)

    affected_functions = []

    for node in ast.walk(tree):

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):

            start_line = node.lineno
            end_line = node.end_lineno

            for changed_line in changed_lines:

                if start_line <= changed_line <= end_line:

                    affected_functions.append(node.name)
                    break

    return affected_functions


def check_security_relevance(file_path, affected_functions):

    with open(file_path, "r", encoding="utf-8") as file:
        source_code = file.read()

    tree = ast.parse(source_code)

    security_keywords = [
        "sql",
        "query",
        "execute",
        "password",
        "token",
        "user",
        "input",
        "request"
    ]

    security_relevant = []

    for node in ast.walk(tree):

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):

            if node.name not in affected_functions:
                continue

            function_source = ast.get_source_segment(
                source_code,
                node
            )

            if function_source:

                function_lower = function_source.lower()

                for keyword in security_keywords:

                    if keyword in function_lower:
                        security_relevant.append(node.name)
                        break

    return security_relevant


def analyze_file(file_path):

    print("\n========================================")
    print(f"Changed File: {file_path}")
    print("========================================")

    changed_lines = get_changed_line_numbers(file_path)

    print("\nChanged Line Numbers:")

    if changed_lines:
        for line in changed_lines:
            print(f"- Line {line}")
    else:
        print("- No changed lines detected")

    affected_functions = find_affected_functions(
        file_path,
        changed_lines
    )

    print("\nAffected Functions:")

    if affected_functions:
        for function in affected_functions:
            print(f"- {function}()")
    else:
        print("- None")

    security_relevant = check_security_relevance(
        file_path,
        affected_functions
    )

    print("\nSecurity-Relevant Functions:")

    if security_relevant:
        for function in security_relevant:
            print(f"- {function}()")
    else:
        print("- None")

    print("\nSecurity Analysis Scope:")

    if security_relevant:
        for function in security_relevant:
            print(f"- {function}()")

        print("\nAnalysis Required: YES")

    else:
        print("- No security-relevant changes detected")
        print("\nAnalysis Required: NO")


def main():

    print("========================================")
    print("Differential Code Analysis")
    print("========================================")

    changed_files = get_changed_files()

    if not changed_files:
        print("\nNo changed Python files detected.")
        return

    print("\nChanged Python Files:")

    for file in changed_files:
        print(f"- {file}")

    for file in changed_files:
        analyze_file(file)


if __name__ == "__main__":
    main()