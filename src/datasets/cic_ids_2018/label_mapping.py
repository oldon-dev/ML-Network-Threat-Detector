def normalize_attack_family(raw_label: str) -> str:
    label = str(raw_label).strip().lower()

    if label == "benign":
        return "benign"

    if "ddos" in label:
        return "ddos"

    if "dos" in label:
        return "dos"

    if "bot" in label:
        return "bot"

    if "bruteforce" in label or "brute force" in label or "ftp-bruteforce" in label or "ssh-bruteforce" in label:
        return "bruteforce"

    if "sql injection" in label or "xss" in label or "web" in label:
        return "web_attack"

    if "infilteration" in label or "infiltration" in label:
        return "infiltration"

    return "other_attack"