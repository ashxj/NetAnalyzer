class TrafficAnalyzer:

    def __init__(self):

        self.port_activity = {}
        self.ssh_attempts = {}

        self.PORT_SCAN_THRESHOLD = 20
        self.SSH_THRESHOLD = 15

    def detect_port_scan(self, packet):

        ip = packet.src_ip
        port = packet.dst_port

        if port is None:
            return False

        if ip not in self.port_activity:
            self.port_activity[ip] = set()

        self.port_activity[ip].add(port)

        if len(self.port_activity[ip]) > self.PORT_SCAN_THRESHOLD:
            return True

        return False

    def detect_ssh_bruteforce(self, packet):

        if packet.dst_port != 22:
            return False

        ip = packet.src_ip

        if ip not in self.ssh_attempts:
            self.ssh_attempts[ip] = 0

        self.ssh_attempts[ip] += 1

        if self.ssh_attempts[ip] > self.SSH_THRESHOLD:
            return True

        return False