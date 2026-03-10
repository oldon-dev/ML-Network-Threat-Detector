from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader

from common.types import PacketInfo


def pcap_packet_stream(pcap_path: str):
    """
    Yield PacketInfo objects from a PCAP file.
    """
    with PcapReader(pcap_path) as reader:
        for packet in reader:
            if IP not in packet:
                continue

            ip = packet[IP]

            protocol = "OTHER"
            src_port = 0
            dst_port = 0
            flags = None

            if TCP in packet:
                protocol = "TCP"
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
                flags = str(packet[TCP].flags)

            elif UDP in packet:
                protocol = "UDP"
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)

            yield PacketInfo(
                timestamp=float(packet.time),
                src_ip=str(ip.src),
                dst_ip=str(ip.dst),
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=len(packet),
                tcp_flags=flags,
            )