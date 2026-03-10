def safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def explain_prediction(features: dict, attack_family: str, suspicious_score: float, family_confidence: float) -> list[str]:
    reasons = []

    forward_packets = features.get("forward_packets", 0)
    reverse_packets = features.get("reverse_packets", 0)
    forward_bytes = features.get("forward_bytes", 0)
    reverse_bytes = features.get("reverse_bytes", 0)
    flow_duration = features.get("flow_duration", 0.0)
    flow_packets_per_second = features.get("flow_packets_per_second", 0.0)
    flow_bytes_per_second = features.get("flow_bytes_per_second", 0.0)
    syn_flag_count = features.get("syn_flag_count", 0)
    avg_packet_size = features.get("average_packet_size", 0.0)
    dst_port = features.get("dst_port", 0)

    packet_ratio = safe_ratio(forward_packets, max(reverse_packets, 1))
    byte_ratio = safe_ratio(forward_bytes, max(reverse_bytes, 1))

    if flow_packets_per_second > 100:
        reasons.append("high packet rate")

    if flow_bytes_per_second > 50000:
        reasons.append("high byte rate")

    if reverse_packets == 0 and forward_packets >= 3:
        reasons.append("one-way traffic pattern")

    if packet_ratio > 5:
        reasons.append("low reverse traffic ratio")

    if byte_ratio > 5:
        reasons.append("asymmetric traffic volume")

    if flow_duration < 1.0 and forward_packets >= 5:
        reasons.append("short burst connection")

    if syn_flag_count >= 3:
        reasons.append("elevated SYN activity")

    if dst_port not in {53, 80, 123, 443}:
        reasons.append("uncommon destination port")

    if avg_packet_size < 100 and forward_packets > 10:
        reasons.append("many small packets")

    if attack_family == "ddos":
        if flow_packets_per_second > 100:
            reasons.append("traffic pattern resembles denial-of-service")
        if reverse_packets <= 1:
            reasons.append("minimal response traffic")

    elif attack_family == "portscan":
        if dst_port not in {80, 443, 53}:
            reasons.append("destination service pattern is unusual")
        if flow_duration < 1.0:
            reasons.append("connection pattern resembles probing")

    elif attack_family == "dos":
        reasons.append("sustained traffic volume resembles DoS behavior")

    elif attack_family == "bruteforce":
        reasons.append("repeated connection pattern may reflect repeated login attempts")

    elif attack_family == "bot":
        reasons.append("traffic pattern resembles automated communication")

    elif attack_family in {"web_attack", "webattack"}:
        reasons.append("flow resembles suspicious web application traffic")

    if suspicious_score >= 0.95:
        reasons.append("very high suspicious score")

    if family_confidence < 0.60:
        reasons.append("low family confidence")

    # Deduplicate while preserving order
    unique_reasons = []
    seen = set()
    for reason in reasons:
        if reason not in seen:
            unique_reasons.append(reason)
            seen.add(reason)

    return unique_reasons[:5]

def get_severity(suspicious_score: float, family_confidence: float) -> str:
    if suspicious_score >= 0.95 and family_confidence >= 0.80:
        return "high"
    if suspicious_score >= 0.85:
        return "medium"
    return "low"