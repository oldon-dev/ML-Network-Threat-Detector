def normalize_ctu_label(label: str) -> str:
    value = str(label).strip().lower()
    value = " ".join(value.split())
    return value


def map_attack_family(label: str) -> str:
    value = normalize_ctu_label(label)

    if "botnet" in value:
        return "bot"

    if "normal" in value or "background" in value:
        return "benign"

    return "unknown"


def binary_target_from_family(family: str) -> int:
    return 0 if family == "benign" else 1