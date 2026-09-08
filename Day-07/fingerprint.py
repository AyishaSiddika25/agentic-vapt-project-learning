import hashlib
import os


def create_fingerprint(finding):
    """
    Create a deterministic fingerprint for a security finding.

    Fingerprint identity:
        rule_id + normalized file path + start_line + end_line

    This matches the finding identity scheme established in Day 6.
    """

    rule_id = finding["rule_id"]
    file_path = os.path.normpath(finding["file"]).replace("\\", "/")
    start_line = finding["start_line"]
    end_line = finding["end_line"]

    identity = (
        f"{rule_id}|"
        f"{file_path}|"
        f"{start_line}|"
        f"{end_line}"
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()