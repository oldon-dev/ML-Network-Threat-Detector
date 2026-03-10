from queue import Empty, Queue

from scapy.all import AsyncSniffer, get_if_list
from scapy.layers.inet import IP, TCP, UDP

from common.types import PacketInfo


def list_interfaces():
    return get_if_list()


def _convert_packet(packet):
    if IP not in packet:
        return None

    ip = packet[IP]
    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    flags = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return PacketInfo(
        timestamp=float(packet.time),
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        size=len(packet),
        tcp_flags=flags,
    )


def packet_stream(interface=None):
    """
    Continuous packet generator for real-time monitoring.
    """
    packet_queue = Queue()

    def handle_packet(packet):
        converted = _convert_packet(packet)
        if converted is not None:
            packet_queue.put(converted)

    sniffer = AsyncSniffer(
        iface=interface,
        prn=handle_packet,
        store=False,
    )
    sniffer.start()

    try:
        while True:
            try:
                yield packet_queue.get(timeout=1.0)
            except Empty:
                continue
    finally:
        sniffer.stop()


def probe_interface(interface: str, seconds: int = 5) -> int:
    """
    Count packets seen on one interface over a short window.
    """
    count = 0

    def handle_packet(_packet):
        nonlocal count
        count += 1

    sniffer = AsyncSniffer(
        iface=interface,
        prn=handle_packet,
        store=False,
    )
    sniffer.start()
    try:
        sniffer.join(timeout=seconds)
    finally:
        sniffer.stop()

    return count


def auto_select_interface(seconds: int = 5) -> tuple[str | None, dict[str, int]]:
    """
    Probe all interfaces and return the one with the most traffic.
    """
    interfaces = list_interfaces()
    counts: dict[str, int] = {}

    for iface in interfaces:
        try:
            counts[iface] = probe_interface(iface, seconds=seconds)
        except Exception:
            counts[iface] = -1

    valid = {iface: count for iface, count in counts.items() if count >= 0}
    if not valid:
        return None, counts

    selected = max(valid, key=valid.get)
    return selected, counts