def normalize_attack_family(raw_label: str) -> str:
    label = str(raw_label).strip().lower()

    if label in {"normal", "benign"}:
        return "benign"

    if "fuzzers" in label:
        return "fuzzer"

    if "analysis" in label:
        return "analysis"

    if "backdoor" in label:
        return "backdoor"

    if "dos" in label:
        return "dos"

    if "exploits" in label or "exploit" in label:
        return "exploit"

    if "generic" in label:
        return "generic"

    if "reconnaissance" in label or "recon" in label:
        return "scan"

    if "shellcode" in label:
        return "shellcode"

    if "worm" in label:
        return "worm"

    return "other_attack"


def to_binary_target(attack_family: str) -> int:
    return 0 if attack_family == "benign" else 1