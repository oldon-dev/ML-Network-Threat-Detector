from src.common.types import PacketInfo
from src.features.extractor import flow_to_features
from src.flows.flow_table import FlowTable


def test_flow_table_groups_bidirectional_packets():
    table = FlowTable(inactive_timeout=5, active_timeout=30)

    packet1 = PacketInfo(
        timestamp=1.0,
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=53,
        protocol="UDP",
        size=100,
    )

    packet2 = PacketInfo(
        timestamp=2.0,
        src_ip="8.8.8.8",
        dst_ip="10.0.0.1",
        src_port=53,
        dst_port=50000,
        protocol="UDP",
        size=150,
    )

    expired = table.consume(packet1)
    assert expired == []

    expired = table.consume(packet2)
    assert expired == []

    assert len(table.flows) == 1

    flow = list(table.flows.values())[0]
    assert flow.forward_packets == 1
    assert flow.reverse_packets == 1
    assert flow.forward_bytes == 100
    assert flow.reverse_bytes == 150


def test_flow_feature_extraction():
    table = FlowTable(inactive_timeout=5, active_timeout=30)

    packets = [
        PacketInfo(
            timestamp=1.0,
            src_ip="10.0.0.1",
            dst_ip="1.1.1.1",
            src_port=40000,
            dst_port=443,
            protocol="TCP",
            size=60,
            tcp_flags="S",
        ),
        PacketInfo(
            timestamp=1.5,
            src_ip="1.1.1.1",
            dst_ip="10.0.0.1",
            src_port=443,
            dst_port=40000,
            protocol="TCP",
            size=60,
            tcp_flags="SA",
        ),
        PacketInfo(
            timestamp=2.0,
            src_ip="10.0.0.1",
            dst_ip="1.1.1.1",
            src_port=40000,
            dst_port=443,
            protocol="TCP",
            size=120,
            tcp_flags="A",
        ),
    ]

    for packet in packets:
        table.consume(packet)

    flow = list(table.flows.values())[0]
    features = flow_to_features(flow)

    assert features["total_packets"] == 3
    assert features["total_bytes"] == 240
    assert features["syn_count"] >= 1
    assert features["ack_count"] >= 1