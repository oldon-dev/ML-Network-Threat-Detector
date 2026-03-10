from dataclasses import dataclass
from typing import Literal, Optional


Protocol = Literal["TCP", "UDP", "ICMP", "OTHER"]
Direction = Literal["forward", "reverse"]


@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    size: int
    tcp_flags: Optional[str] = None