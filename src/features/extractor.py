from statistics import mean, pstdev

from flows.flow_record import FlowRecord


def _safe_mean(values: list[float | int]) -> float:
    return mean(values) if values else 0.0


def _safe_std(values: list[float | int]) -> float:
    return pstdev(values) if len(values) > 1 else 0.0


def _inter_arrival_stats(timestamps: list[float]) -> tuple[float, float, float, float]:
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0

    ts = sorted(timestamps)
    intervals = [ts[i] - ts[i - 1] for i in range(1, len(ts))]

    return (
        _safe_mean(intervals),
        _safe_std(intervals),
        max(intervals),
        min(intervals),
    )


def _iat_total(timestamps: list[float]) -> float:
    if len(timestamps) < 2:
        return 0.0
    ts = sorted(timestamps)
    return ts[-1] - ts[0]


def flow_to_features(flow: FlowRecord) -> dict:
    duration = max(flow.duration(), 0.001)

    total_packets = flow.total_packets()
    total_bytes = flow.total_bytes()

    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _inter_arrival_stats(flow.packet_timestamps)

    fwd_packet_length_mean = _safe_mean(flow.forward_packet_sizes)
    bwd_packet_length_mean = _safe_mean(flow.reverse_packet_sizes)

    min_packet_length = min(flow.all_packet_sizes) if flow.all_packet_sizes else 0.0
    max_packet_length = max(flow.all_packet_sizes) if flow.all_packet_sizes else 0.0
    packet_length_mean = _safe_mean(flow.all_packet_sizes)
    packet_length_std = _safe_std(flow.all_packet_sizes)

    return {
        "dst_port": flow.dst_port,
        "flow_duration": duration,
        "forward_packets": flow.forward_packets,
        "reverse_packets": flow.reverse_packets,
        "forward_bytes": flow.forward_bytes,
        "reverse_bytes": flow.reverse_bytes,
        "fwd_packet_length_mean": fwd_packet_length_mean,
        "bwd_packet_length_mean": bwd_packet_length_mean,
        "flow_bytes_per_second": total_bytes / duration,
        "flow_packets_per_second": total_packets / duration,
        "flow_iat_mean": flow_iat_mean,
        "flow_iat_std": flow_iat_std,
        "flow_iat_max": flow_iat_max,
        "flow_iat_min": flow_iat_min,
        "fwd_iat_total": _iat_total(flow.forward_timestamps),
        "bwd_iat_total": _iat_total(flow.reverse_timestamps),
        "fwd_packets_per_second": flow.forward_packets / duration,
        "bwd_packets_per_second": flow.reverse_packets / duration,
        "min_packet_length": min_packet_length,
        "max_packet_length": max_packet_length,
        "packet_length_mean": packet_length_mean,
        "packet_length_std": packet_length_std,
        "fin_flag_count": flow.fin_count,
        "syn_flag_count": flow.syn_count,
        "ack_flag_count": flow.ack_count,
        "average_packet_size": total_bytes / max(total_packets, 1),
    }