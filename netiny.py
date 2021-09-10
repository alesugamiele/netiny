import socket
import struct
import sys

class Colors:
    default: str = "\x1b[38;5;255m"
    green: str = "\x1b[38;5;2m"


class Ethernet:
    protocols: dict[int, str] = {
        0x800: "IPv4",
        0x806: "ARP",
        0x8035: "RARP",
        0x86dd: "IPv6",
    }


class IPV4:
    protocols: dict[int, str] = {
        0x11: "UDP",
        0x6: "TCP",
        0x1: "ICMP",
        0x29: "IPv6",
    }


class Capture:
    def __init__(
            self, show_http: bool = False,
            block_protocol: str = None) -> None:
        self.network_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
        )
        self.packet_counter = self.total_packets_size = 0
        self.show_http = show_http
        self.block_protocol = block_protocol
        self.start()

    def _pass_filter_packet_protocol(self, protocol: str) -> bool:
        if self.block_protocol is not None:
            return False if self.block_protocol.upper() in protocol.upper() \
                    else True
        return True

    def start(self) -> None:
        while True:
            try:
                source_port = destination_port = http_packet = None
                packet, _ = self.network_socket.recvfrom(1514)
                if b"HTTP" in packet:
                    http_packet = packet[66:]
                default_ethernet_address = packet[:12]
                destination_address, source_address = map(
                    lambda mac_as_byte: ":".join("%02x" % _ for _ in mac_as_byte),
                    struct.unpack("!6s6s", default_ethernet_address)
                )
                protocol_header = packet[12:14]
                used_protocol = struct.unpack("!H", protocol_header)[0]
                if used_protocol in Ethernet.protocols:
                    used_protocol = Ethernet.protocols[used_protocol]
                    if used_protocol == "IPv4":
                        address_header = packet[26:34]
                        source_address, destination_address = map(
                            lambda ip_as_byte: socket.inet_ntoa(ip_as_byte),
                            struct.unpack("!4s4s", address_header)
                        )
                        protocol_ipv4 = packet[23]
                        used_protocol += "->{}".format(
                            IPV4.protocols[protocol_ipv4] if protocol_ipv4 in IPV4.protocols \
                            else protocol_ipv4
                        )
                        if protocol_ipv4 in (0x6, 0x11):
                            ports_header = packet[34:38]
                            source_port, destination_port = struct.unpack("!2H", ports_header)
                if self._pass_filter_packet_protocol(used_protocol):
                    print(
                        "{counter} [{proto}] {src_a}{src_p} - {dst_a}{dst_p}".format(
                            counter=self.packet_counter,
                            proto=used_protocol,
                            src_a=source_address,
                            src_p=":" + str(source_port) if source_port is not None else "",
                            dst_a=destination_address,
                            dst_p=":" + str(destination_port) if destination_port is not None else ""
                        )
                    )
                    self.packet_counter += 1
                    self.total_packets_size += len(packet)
                if http_packet is not None and self.show_http:
                    print("{clr_green}{pckt_content}{clr_default}".format(
                        clr_green=Colors.green,
                        pckt_content=http_packet.decode("utf-8", errors="ignore"),
                        clr_default=Colors.default
                    ))
            except KeyboardInterrupt:
                print("\nTotal caught packets size: {} MB".format(
                    round(self.total_packets_size/1e6, 2)
                ))
                self.stop()

    def stop(self) -> None:
        self.network_socket.close()
        sys.exit(0)


if __name__ == "__main__":
    show_http_packets = False
    to_block_protocol = None

    if len(sys.argv) > 1:
        if "http" in sys.argv:
            show_http_packets = True
        block_procol_arg = [
            arg for arg in sys.argv \
                if arg.startswith(("-b=", "--block="))
        ]
        if block_procol_arg:
            to_block_protocol = block_procol_arg[0].split("=")[1]
        if "-h" in sys.argv or "--help" in sys.argv:
            print(f"""
Usage: {sys.argv[0]} [Options]

http: Show all HTTP requests
-b --block: Not show a specified protocol. ex. -b=tcp
""")
            sys.exit(0)
    Capture(
        show_http=show_http_packets,
        block_protocol=to_block_protocol
    )
