from scapy.all import AsyncSniffer


class PacketCapture:

    def __init__(self, interface):
        self.interface = interface
        self.sniffer = None

    def start_capture(self, callback):
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=callback,
            store=False
        )
        self.sniffer.start()

    def stop_capture(self):
        if self.sniffer is not None and self.sniffer.running:
            self.sniffer.stop()
