from collections import defaultdict


class TrafficStats:

    def __init__(self):

        self.total_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0

        self.src_ip_counter = defaultdict(int)

    def update(self, packet):

        self.total_packets += 1

        if packet.protocol == 6:
            self.tcp_packets += 1
        elif packet.protocol == 17:
            self.udp_packets += 1

        self.src_ip_counter[packet.src_ip] += 1

    def print_stats(self):

        print("\n=== Traffic Stats ===")

        print(f"Total packets: {self.total_packets}")
        print(f"TCP packets: {self.tcp_packets}")
        print(f"UDP packets: {self.udp_packets}")

    def snapshot(self):

        return {
            "total_packets": self.total_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets
        }

    def top_sources(self, limit=5):

        print("\n=== Top Source IPs ===")

        sorted_ips = self.top_sources_data(limit)

        for ip, count in sorted_ips:
            print(f"{ip} → {count} packets")

    def top_sources_data(self, limit=5):

        sorted_ips = sorted(
            self.src_ip_counter.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return sorted_ips[:limit]
