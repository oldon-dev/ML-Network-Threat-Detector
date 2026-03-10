def normalize_attack_family(raw_label: str) -> str:
    label = str(raw_label).strip().lower()

    if label in {"normal", "benign"}:
        return "benign"

    if "backdoor" in label:
        return "backdoor"

    if "ddos" in label:
        return "ddos"

    if label == "dos":
        return "dos"

    if "injection" in label:
        return "injection"

    if "password" in label:
        return "password"

    if "ransomware" in label:
        return "ransomware"

    if "scanning" in label or "scan" in label:
        return "scan"

    if "xss" in label:
        return "xss"

    return "other_attack"