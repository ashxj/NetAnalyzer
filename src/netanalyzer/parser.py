from scapy.layers.inet import IP, TCP, UDP


class ParsedPacket:

    def __init__(self, src_ip, dst_ip, protocol, src_port=None, dst_port=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port


def parse_packet(packet):

    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    src_port = None
    dst_port = None

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    return ParsedPacket(src_ip, dst_ip, protocol, src_port, dst_port)