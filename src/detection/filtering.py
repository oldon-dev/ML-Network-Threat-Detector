from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

from common.config import (
    ALLOW_PRIVATE_TO_PRIVATE,
    MIN_BYTES_FOR_SCORING,
    MIN_PACKETS_FOR_SCORING,
    SKIP_BROADCAST,
    SKIP_LOOPBACK,
    SKIP_MULTICAST,
)
from features.extractor import flow_to_features
from flows.flow_record import FlowRecord


PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]

LINK_LOCAL_NETWORKS = [
    ip_network("169.254.0.0/16"),
]

MULTICAST_NETWORKS = [
    ip_network("224.0.0.0/4"),
]

BROADCAST_ADDRESSES = {
    "255.255.255.255",
}


@dataclass
class FilterDecision:
    skip: bool
    reason: str
    tags: list[str] = field(default_factory=list)


def _safe_ip(ip: str):
    try:
        return ip_address(ip)
    except ValueError:
        return None


def is_private_ip(ip: str) -> bool:
    obj = _safe_ip(ip)
    if obj is None:
        return False
    return any(obj in net for net in PRIVATE_NETWORKS)


def is_link_local_ip(ip: str) -> bool:
    obj = _safe_ip(ip)
    if obj is None:
        return False
    return any(obj in net for net in LINK_LOCAL_NETWORKS)


def is_multicast_ip(ip: str) -> bool:
    obj = _safe_ip(ip)
    if obj is None:
        return False
    return any(obj in net for net in MULTICAST_NETWORKS)


def is_loopback_ip(ip: str) -> bool:
    obj = _safe_ip(ip)
    if obj is None:
        return False
    return obj.is_loopback


def is_broadcast_ip(ip: str) -> bool:
    return ip in BROADCAST_ADDRESSES


def classify_flow_context(flow: FlowRecord, features: dict) -> list[str]:
    tags: list[str] = []

    if is_private_ip(flow.src_ip):
        tags.append("src_private")
    if is_private_ip(flow.dst_ip):
        tags.append("dst_private")

    if is_link_local_ip(flow.src_ip) or is_link_local_ip(flow.dst_ip):
        tags.append("link_local")

    if flow.protocol == "UDP" and flow.dst_port == 53:
        tags.append("dns")

    if flow.protocol == "TCP" and flow.dst_port == 443:
        tags.append("https")

    if flow.protocol == "TCP" and flow.dst_port == 80:
        tags.append("http")

    if flow.dst_port >= 49152:
        tags.append("ephemeral_dst_port")

    if features["reverse_packets"] == 0:
        tags.append("one_way")

    if features["flow_duration"] < 1.0:
        tags.append("short_flow")

    if features["flow_packets_per_second"] > 200:
        tags.append("high_packet_rate")

    if features["flow_bytes_per_second"] > 100000:
        tags.append("high_byte_rate")

    return tags


def should_skip_flow(flow: FlowRecord) -> FilterDecision:
    features = flow_to_features(flow)
    tags = classify_flow_context(flow, features)

    total_packets = flow.total_packets()
    total_bytes = flow.total_bytes()

    if SKIP_LOOPBACK and (is_loopback_ip(flow.src_ip) or is_loopback_ip(flow.dst_ip)):
        return FilterDecision(skip=True, reason="loopback traffic", tags=tags)

    if SKIP_MULTICAST and (is_multicast_ip(flow.src_ip) or is_multicast_ip(flow.dst_ip)):
        return FilterDecision(skip=True, reason="multicast traffic", tags=tags)

    if SKIP_BROADCAST and (is_broadcast_ip(flow.src_ip) or is_broadcast_ip(flow.dst_ip)):
        return FilterDecision(skip=True, reason="broadcast traffic", tags=tags)

    if total_packets < MIN_PACKETS_FOR_SCORING:
        return FilterDecision(skip=True, reason="too few packets", tags=tags)

    if total_bytes < MIN_BYTES_FOR_SCORING:
        return FilterDecision(skip=True, reason="too few bytes", tags=tags)

    if features["flow_duration"] < 0:
        return FilterDecision(skip=True, reason="invalid negative duration", tags=tags)

    if not ALLOW_PRIVATE_TO_PRIVATE:
        if is_private_ip(flow.src_ip) and is_private_ip(flow.dst_ip):
            return FilterDecision(skip=True, reason="private-to-private disabled", tags=tags)

    return FilterDecision(skip=False, reason="candidate for detection", tags=tags)