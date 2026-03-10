from scapy.all import get_if_list, sniff


def probe_interface(interface, timeout=5):
    count = 0

    def count_packet(packet):
        nonlocal count
        count += 1

    try:
        sniff(iface=interface, prn=count_packet, store=False, timeout=timeout)
        return count
    except Exception as e:
        print(f"Error on {interface}: {e}")
        return -1


def main():
    interfaces = get_if_list()

    print("Probing interfaces...\n")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] Testing {iface} ...")
        count = probe_interface(iface, timeout=5)
        print(f"    Packets captured: {count}\n")


if __name__ == "__main__":
    main()