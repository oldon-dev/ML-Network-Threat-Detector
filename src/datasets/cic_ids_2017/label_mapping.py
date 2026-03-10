def normalize_raw_label(label: str) -> str:
    value = str(label).strip().lower()
    value = value.replace("–", "-")
    value = value.replace("—", "-")
    value = " ".join(value.split())
    return value


def map_attack_family(label: str) -> str:
    value = normalize_raw_label(label)

    if value == "benign":
        return "benign"

    if value == "ddos":
        return "ddos"

    if value == "portscan":
        return "portscan"

    if value == "bot":
        return "bot"

    if value == "heartbleed":
        return "heartbleed"

    if value == "infiltration":
        return "infiltration"

    if value in {"ftp-patator", "ssh-patator"}:
        return "bruteforce"

    if value in {
        "web attack - brute force",
        "web attack - xss",
        "web attack - sql injection",
    }:
        return "webattack"

    if value in {
        "dos hulk",
        "dos goldeneye",
        "dos slowloris",
        "dos slowhttptest",
    }:
        return "dos"

    return "unknown"


def binary_target_from_family(family: str) -> int:
    return 0 if family == "benign" else 1