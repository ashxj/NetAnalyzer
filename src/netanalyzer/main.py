import curses
from pathlib import Path

from scapy.all import get_if_list

from .capture import PacketCapture
from .parser import parse_packet
from .analyzer import TrafficAnalyzer
from .stats import TrafficStats
from .geoip import GeoIPResolver
from .tui import NetAnalyzerTUI


INTERFACE = "wlan0"


analyzer = TrafficAnalyzer()
stats = TrafficStats()


BASE_DIR = Path(__file__).resolve().parent
GEO_DB = BASE_DIR / "data" / "GeoLite2-Country.mmdb"

geo = GeoIPResolver(str(GEO_DB))
capture = PacketCapture(INTERFACE)
ui = NetAnalyzerTUI(stats, INTERFACE)


def handle_packet(packet):

    parsed = parse_packet(packet)

    if parsed is None:
        return

    country = geo.get_country(parsed.src_ip)

    stats.update(parsed)
    ui.add_log(
        f"{parsed.src_ip} ({country}) -> {parsed.dst_ip}:{parsed.dst_port}"
    )

    if analyzer.detect_port_scan(parsed):
        message = f"Port scan detected from {parsed.src_ip}"
        ui.add_alert(message)

    if analyzer.detect_ssh_bruteforce(parsed):
        message = f"Possible SSH brute force from {parsed.src_ip}"
        ui.add_alert(message)


def list_interfaces():

    return sorted(get_if_list())


def switch_interface(interface):

    global capture

    if interface == capture.interface:
        ui.add_log(f"[WARNING] Interface {interface} is already active")
        return

    previous_interface = capture.interface
    capture.stop_capture()

    try:
        new_capture = PacketCapture(interface)
        new_capture.start_capture(handle_packet)
    except Exception:
        fallback_capture = PacketCapture(previous_interface)
        fallback_capture.start_capture(handle_packet)
        capture = fallback_capture
        ui.interface = previous_interface
        raise

    capture = new_capture
    ui.interface = interface
    ui.add_info(f"Packet capture switched to interface {interface}")


def main():

    ui.set_interface_actions(list_interfaces, switch_interface)
    ui.add_info(f"Packet capture on interface {INTERFACE} started")

    try:
        capture.start_capture(handle_packet)
        curses.wrapper(ui.render)
    finally:
        ui.running = False
        capture.stop_capture()
        print("\nStopping capture...")
        stats.print_stats()
        stats.top_sources()


if __name__ == "__main__":
    main()
