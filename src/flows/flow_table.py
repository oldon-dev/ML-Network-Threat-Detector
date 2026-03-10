from common.types import PacketInfo
from flows.flow_key import FlowKey
from flows.flow_record import FlowRecord


class FlowTable:
    def __init__(self, inactive_timeout: int = 15, active_timeout: int = 120):
        self.inactive_timeout = inactive_timeout
        self.active_timeout = active_timeout
        self.flows: dict[FlowKey, FlowRecord] = {}

    def consume(self, packet: PacketInfo) -> list[FlowRecord]:
        """
        Accept one packet, update or create its flow, and return
        any flows that have expired.
        """
        expired_flows = self.expire_flows(packet.timestamp)

        flow_key = FlowKey.from_endpoints(
            src_ip=packet.src_ip,
            src_port=packet.src_port,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

        if flow_key not in self.flows:
            self.flows[flow_key] = FlowRecord(
                src_ip=packet.src_ip,
                src_port=packet.src_port,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_ts=packet.timestamp,
                last_seen_ts=packet.timestamp,
            )

        flow = self.flows[flow_key]

        is_forward = (
            packet.src_ip == flow.src_ip
            and packet.src_port == flow.src_port
            and packet.dst_ip == flow.dst_ip
            and packet.dst_port == flow.dst_port
        )

        if is_forward:
            flow.update_forward(
                packet_size=packet.size,
                timestamp=packet.timestamp,
                tcp_flags=packet.tcp_flags,
            )
        else:
            flow.update_reverse(
                packet_size=packet.size,
                timestamp=packet.timestamp,
                tcp_flags=packet.tcp_flags,
            )

        return expired_flows

    def expire_flows(self, current_time: float) -> list[FlowRecord]:
        expired = []
        keys_to_remove = []

        for key, flow in self.flows.items():
            inactive_age = current_time - flow.last_seen_ts
            active_age = current_time - flow.start_ts

            if inactive_age >= self.inactive_timeout or active_age >= self.active_timeout:
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.flows[key]

        return expired

    def flush_all(self) -> list[FlowRecord]:
        remaining = list(self.flows.values())
        self.flows.clear()
        return remaining