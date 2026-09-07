import hashlib


def create_fingerprint(finding):
    identity = (
        f"{finding['rule_id']}|"
        f"{finding['file']}|"
        f"{finding['line']}"
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()