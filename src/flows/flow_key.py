from dataclasses import dataclass


@dataclass(frozen=True)
class FlowKey:
    ip_a: str
    port_a: int
    ip_b: str
    port_b: int
    protocol: str

    @staticmethod
    def from_endpoints(
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> "FlowKey":
        left = (src_ip, src_port)
        right = (dst_ip, dst_port)

        if left <= right:
            return FlowKey(
                ip_a=src_ip,
                port_a=src_port,
                ip_b=dst_ip,
                port_b=dst_port,
                protocol=protocol,
            )

        return FlowKey(
            ip_a=dst_ip,
            port_a=dst_port,
            ip_b=src_ip,
            port_b=src_port,
            protocol=protocol,
        )