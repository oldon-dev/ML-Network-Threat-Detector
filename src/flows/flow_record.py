from dataclasses import dataclass, field


@dataclass
class FlowRecord:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_ts: float
    last_seen_ts: float

    forward_packets: int = 0
    reverse_packets: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    packet_timestamps: list[float] = field(default_factory=list)
    forward_timestamps: list[float] = field(default_factory=list)
    reverse_timestamps: list[float] = field(default_factory=list)

    forward_packet_sizes: list[int] = field(default_factory=list)
    reverse_packet_sizes: list[int] = field(default_factory=list)
    all_packet_sizes: list[int] = field(default_factory=list)

    def update_forward(self, packet_size: int, timestamp: float, tcp_flags: str | None = None) -> None:
        self.forward_packets += 1
        self.forward_bytes += packet_size
        self.last_seen_ts = timestamp

        self.packet_timestamps.append(timestamp)
        self.forward_timestamps.append(timestamp)

        self.forward_packet_sizes.append(packet_size)
        self.all_packet_sizes.append(packet_size)

        self._update_tcp_flags(tcp_flags)

    def update_reverse(self, packet_size: int, timestamp: float, tcp_flags: str | None = None) -> None:
        self.reverse_packets += 1
        self.reverse_bytes += packet_size
        self.last_seen_ts = timestamp

        self.packet_timestamps.append(timestamp)
        self.reverse_timestamps.append(timestamp)

        self.reverse_packet_sizes.append(packet_size)
        self.all_packet_sizes.append(packet_size)

        self._update_tcp_flags(tcp_flags)

    def duration(self) -> float:
        return max(self.last_seen_ts - self.start_ts, 0.0)

    def total_packets(self) -> int:
        return self.forward_packets + self.reverse_packets

    def total_bytes(self) -> int:
        return self.forward_bytes + self.reverse_bytes

    def _update_tcp_flags(self, tcp_flags: str | None) -> None:
        if not tcp_flags:
            return

        flags = tcp_flags.upper()

        if "S" in flags:
            self.syn_count += 1
        if "A" in flags:
            self.ack_count += 1
        if "F" in flags:
            self.fin_count += 1
        if "R" in flags:
            self.rst_count += 1
        if "P" in flags:
            self.psh_count += 1