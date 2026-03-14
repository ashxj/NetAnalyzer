import curses
from datetime import datetime
import time
from collections import deque
from threading import Lock

try:
    from colorama import init as colorama_init
except ImportError:
    colorama_init = None


class NetAnalyzerTUI:

    APP_NAME = "NetAnalyzer"
    APP_VERSION = "0.1.0"
    PANELS = ("connections", "alerts")

    def __init__(self, stats, interface, log_limit=500):
        self.stats = stats
        self.interface = interface
        self.log_lines = deque(maxlen=log_limit)
        self.alert_lines = deque(maxlen=100)
        self.lock = Lock()
        self.running = True
        self.list_interfaces = lambda: []
        self.switch_interface = lambda interface: None
        self.selected_interface = 0
        self.focused_panel = "connections"
        self.scroll_offsets = {
            "connections": 0,
            "alerts": 0
        }

        if colorama_init is not None:
            colorama_init()

    def set_interface_actions(self, list_interfaces, switch_interface):
        self.list_interfaces = list_interfaces
        self.switch_interface = switch_interface

    def add_log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        with self.lock:
            if self.scroll_offsets["connections"] > 0:
                self.scroll_offsets["connections"] += 1
            self.log_lines.appendleft(f"[{timestamp}] {message}")

    def add_info(self, message):
        self.add_log(f"[INFO] {message}")

    def add_alert(self, message):
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] [ALERT] {message}"
        with self.lock:
            if self.scroll_offsets["alerts"] > 0:
                self.scroll_offsets["alerts"] += 1
            self.alert_lines.appendleft(entry)

    def clear_logs(self):
        with self.lock:
            self.log_lines.clear()
            self.alert_lines.clear()
            self.scroll_offsets["connections"] = 0
            self.scroll_offsets["alerts"] = 0
        self.add_info("Logs cleared")

    def render(self, screen):
        curses.curs_set(0)
        screen.nodelay(True)
        screen.timeout(250)
        self._init_colors()

        while self.running:
            key = screen.getch()
            if key in (ord("q"), ord("Q")):
                self.running = False
                break
            if key in (ord("s"), ord("S")):
                self.save_snapshot(screen)
            if key in (ord("w"), ord("W")):
                self.show_interface_modal(screen)
            if key in (ord("c"), ord("C")):
                self.clear_logs()
            if key == 9:
                self.focus_next_panel()
            if key in (curses.KEY_UP, ord("k"), ord("K")):
                self.scroll_panel(-1)
            if key in (curses.KEY_DOWN, ord("j"), ord("J")):
                self.scroll_panel(1)
            if key in (ord("l"), ord("L")):
                self.follow_live()
            if key == curses.KEY_PPAGE:
                self.scroll_panel(-(self._current_page_size(screen) - 1))
            if key == curses.KEY_NPAGE:
                self.scroll_panel(self._current_page_size(screen) - 1)
            if key == ord("g"):
                self.scroll_to_edge(oldest=True)
            if key == ord("G"):
                self.scroll_to_edge(oldest=False)

            self._draw(screen)

        self._draw(screen)

    def _draw(self, screen):
        screen.erase()

        height, width = screen.getmaxyx()
        if height < 3 or width < 20:
            self._safe_addnstr(screen, 0, 0, "Terminal is too small", max(width - 1, 1))
            screen.refresh()
            return

        content_height = height - 1

        if width >= 80 and content_height >= 10:
            self._draw_columns(screen, content_height, width)
        else:
            self._draw_stacked(screen, content_height, width)

        self._draw_footer(screen, height - 1, width)

        screen.refresh()

    def _draw_columns(self, screen, height, width):
        sidebar_width = max(46, min(66, int(width * 0.48)))
        log_width = width - sidebar_width

        if log_width < 30:
            self._draw_stacked(screen, height, width)
            return

        alerts_height = max(7, min(10, height // 3))
        stats_height = height - alerts_height

        self._draw_logs(screen, 0, 0, height, log_width)
        self._draw_stats(screen, 0, log_width, stats_height, sidebar_width)
        self._draw_alerts(screen, stats_height, log_width, alerts_height, sidebar_width)

    def _draw_stacked(self, screen, height, width):
        stats_height = max(8, min(10, height // 4))
        alerts_height = max(7, min(9, height // 4))
        log_height = height - stats_height - alerts_height

        if log_height < 4:
            self._draw_logs(screen, 0, 0, height, width)
            return

        self._draw_logs(screen, 0, 0, log_height, width)
        self._draw_stats(screen, log_height, 0, stats_height, width)
        self._draw_alerts(screen, log_height + stats_height, 0, alerts_height, width)

    def _draw_logs(self, screen, start_y, start_x, height, width):
        title = " Connections * " if self.focused_panel == "connections" else " Connections "
        title_attr = self.modal_attr if self.focused_panel == "connections" else self.normal_attr
        self._draw_box(screen, start_y, start_x, height, width, title, title_attr)

        usable_height = max(height - 2, 1)
        usable_width = max(width - 2, 1)

        with self.lock:
            all_lines = list(self.log_lines)

        offset = self._clamp_offset("connections", len(all_lines), usable_height)
        lines = all_lines[offset:offset + usable_height]

        if not lines:
            self._safe_addnstr(
                screen,
                start_y + 1,
                start_x + 1,
                "Waiting for packets...",
                usable_width
            )
            return

        for index, line in enumerate(lines, start=1):
            if index >= height - 1:
                break
            self._safe_addnstr(
                screen,
                start_y + index,
                start_x + 1,
                line,
                usable_width,
                self._get_log_color(line)
            )

    def _draw_stats(self, screen, start_y, start_x, height, width):
        self._draw_box(screen, start_y, start_x, height, width, " Stats ", self.normal_attr)

        stats = self.stats.snapshot()
        top_sources = self.stats.top_sources_data(limit=max(height - 9, 1))
        usable_width = max(width - 2, 1)

        lines = [
            f"Interface: {self.interface}",
            f"Total packets: {stats['total_packets']}",
            f"TCP packets:   {stats['tcp_packets']}",
            f"UDP packets:   {stats['udp_packets']}",
            "",
            "Top source IPs:"
        ]

        for ip, count in top_sources:
            lines.append(f"{ip} [{count}]")

        for index, line in enumerate(lines, start=1):
            if index >= height - 1:
                break
            self._safe_addnstr(screen, start_y + index, start_x + 1, line, usable_width)

    def _draw_alerts(self, screen, start_y, start_x, height, width):
        title = " Alerts * " if self.focused_panel == "alerts" else " Alerts "
        title_attr = self.modal_attr if self.focused_panel == "alerts" else self.normal_attr
        self._draw_box(screen, start_y, start_x, height, width, title, title_attr)
        usable_height = max(height - 2, 1)
        usable_width = max(width - 2, 1)

        with self.lock:
            all_alerts = list(self.alert_lines)

        offset = self._clamp_offset("alerts", len(all_alerts), usable_height)
        alerts = all_alerts[offset:offset + usable_height]

        if not alerts:
            self._safe_addnstr(
                screen,
                start_y + 1,
                start_x + 1,
                "No alerts yet",
                usable_width
            )
            return

        for index, line in enumerate(alerts, start=1):
            if index >= height - 1:
                break
            self._safe_addnstr(
                screen,
                start_y + index,
                start_x + 1,
                line,
                usable_width,
                self.alert_attr
            )

    def _draw_footer(self, screen, y, width):
        footer = (
            f" {self.APP_NAME} v{self.APP_VERSION} | "
            "q quit | s save | w interface | c clear | Tab focus | j/k scroll | l live "
        )
        attr = self.modal_attr if hasattr(self, "modal_attr") else curses.A_REVERSE
        self._safe_hline(screen, y, 0, " ", width)
        self._safe_addnstr(screen, y, 0, footer, max(width - 1, 1), attr)

    def _draw_box(self, screen, start_y, start_x, height, width, title, title_attr=0):
        if height < 3 or width < 4:
            return

        self._safe_addch(screen, start_y, start_x, curses.ACS_ULCORNER)
        self._safe_hline(screen, start_y, start_x + 1, curses.ACS_HLINE, width - 2)
        self._safe_addch(screen, start_y, start_x + width - 1, curses.ACS_URCORNER)

        for row in range(start_y + 1, start_y + height - 1):
            self._safe_addch(screen, row, start_x, curses.ACS_VLINE)
            self._safe_addch(screen, row, start_x + width - 1, curses.ACS_VLINE)

        self._safe_addch(screen, start_y + height - 1, start_x, curses.ACS_LLCORNER)
        self._safe_hline(
            screen,
            start_y + height - 1,
            start_x + 1,
            curses.ACS_HLINE,
            width - 2
        )
        self._safe_addch(
            screen,
            start_y + height - 1,
            start_x + width - 1,
            curses.ACS_LRCORNER
        )

        if width > len(title) + 4:
            self._safe_addnstr(screen, start_y, start_x + 2, title, width - 4, title_attr)

    def _safe_addch(self, screen, y, x, char):
        try:
            screen.addch(y, x, char)
        except curses.error:
            pass

    def _safe_addnstr(self, screen, y, x, text, limit, attr=0):
        try:
            screen.addnstr(y, x, text, limit, attr)
        except curses.error:
            pass

    def _safe_hline(self, screen, y, x, char, count):
        if count <= 0:
            return
        try:
            screen.hline(y, x, char, count)
        except curses.error:
            pass

    def _init_colors(self):
        if not curses.has_colors():
            self.normal_attr = 0
            self.info_attr = 0
            self.warning_attr = 0
            self.alert_attr = curses.A_BOLD
            self.modal_attr = curses.A_REVERSE
            return

        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)

        self.normal_attr = 0
        self.info_attr = curses.color_pair(1) | curses.A_BOLD
        self.warning_attr = curses.color_pair(2) | curses.A_BOLD
        self.alert_attr = curses.color_pair(3) | curses.A_BOLD
        self.modal_attr = curses.color_pair(4) | curses.A_BOLD

    def _get_log_color(self, line):
        upper_line = line.upper()
        if "[ALERT]" in upper_line:
            return self.alert_attr
        if "[INFO]" in upper_line:
            return self.info_attr
        if "[WARNING]" in upper_line or "[WARN]" in upper_line:
            return self.warning_attr
        return self.normal_attr

    def save_snapshot(self, screen):
        snapshot = self.build_log_dump()
        filename = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.log")

        with open(filename, "w", encoding="utf-8") as log_file:
            log_file.write(snapshot)
            log_file.write("\n")

        self.add_info(f"Log saved to {filename}")

    def build_log_dump(self):
        stats = self.stats.snapshot()
        top_sources = self.stats.top_sources_data()

        with self.lock:
            connections = list(reversed(self.log_lines))
            alerts = list(reversed(self.alert_lines))

        lines = [
            f"Saved at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Interface: {self.interface}",
            "",
            "=== Stats ===",
            f"Total packets: {stats['total_packets']}",
            f"TCP packets: {stats['tcp_packets']}",
            f"UDP packets: {stats['udp_packets']}",
            "",
            "=== Top Source IPs ==="
        ]

        if top_sources:
            for ip, count in top_sources:
                lines.append(f"{ip} [{count}]")
        else:
            lines.append("No source IP data")

        lines.append("")
        lines.append("=== Alerts ===")

        if alerts:
            lines.extend(alerts)
        else:
            lines.append("No alerts")

        lines.append("")
        lines.append("=== Connections ===")

        if connections:
            lines.extend(connections)
        else:
            lines.append("No connections captured")

        return "\n".join(lines)

    def show_interface_modal(self, screen):
        interfaces = self.list_interfaces()
        if not interfaces:
            self.add_log("[WARNING] No interfaces found")
            return

        try:
            self.selected_interface = interfaces.index(self.interface)
        except ValueError:
            self.selected_interface = 0

        height, width = screen.getmaxyx()
        modal_width = max(30, min(50, width - 6))
        modal_height = max(8, min(len(interfaces) + 4, height - 4))
        start_y = max((height - modal_height) // 2, 0)
        start_x = max((width - modal_width) // 2, 0)

        modal = curses.newwin(modal_height, modal_width, start_y, start_x)
        modal.keypad(True)

        while True:
            self._draw(screen)
            self._draw_modal(modal, interfaces)
            key = modal.getch()

            if key in (27, ord("q"), ord("Q")):
                break
            if key == curses.KEY_UP:
                self.selected_interface = (self.selected_interface - 1) % len(interfaces)
            if key == curses.KEY_DOWN:
                self.selected_interface = (self.selected_interface + 1) % len(interfaces)
            if key in (10, 13, curses.KEY_ENTER):
                selected = interfaces[self.selected_interface]
                try:
                    self.switch_interface(selected)
                except Exception as exc:
                    self.add_log(f"[WARNING] Failed to switch interface: {exc}")
                break

        screen.touchwin()
        screen.refresh()

    def focus_next_panel(self):
        current_index = self.PANELS.index(self.focused_panel)
        self.focused_panel = self.PANELS[(current_index + 1) % len(self.PANELS)]

    def scroll_panel(self, delta):
        self.scroll_offsets[self.focused_panel] += delta

    def follow_live(self):
        self.scroll_offsets[self.focused_panel] = 0

    def scroll_to_edge(self, oldest):
        if oldest:
            self.scroll_offsets[self.focused_panel] = 10**9
            return
        self.scroll_offsets[self.focused_panel] = 0

    def _current_page_size(self, screen):
        height, width = screen.getmaxyx()
        content_height = max(height - 1, 1)

        if width >= 80 and content_height >= 10:
            if self.focused_panel == "connections":
                return max(content_height - 2, 1)
            alerts_height = max(7, min(10, content_height // 3))
            return max(alerts_height - 2, 1)

        if self.focused_panel == "connections":
            stats_height = max(8, min(10, content_height // 4))
            alerts_height = max(7, min(9, content_height // 4))
            log_height = content_height - stats_height - alerts_height
            return max(log_height - 2, 1)

        alerts_height = max(7, min(9, content_height // 4))
        return max(alerts_height - 2, 1)

    def _clamp_offset(self, panel, total_lines, visible_lines):
        max_offset = max(total_lines - visible_lines, 0)
        current_offset = self.scroll_offsets[panel]
        current_offset = max(0, min(current_offset, max_offset))
        self.scroll_offsets[panel] = current_offset
        return current_offset

    def _draw_modal(self, modal, interfaces):
        modal.erase()
        height, width = modal.getmaxyx()
        self._draw_box(modal, 0, 0, height, width, " Interfaces ")
        self._safe_addnstr(modal, 1, 2, "Use arrows and Enter", max(width - 4, 1), self.modal_attr)

        visible_rows = max(height - 4, 1)
        start_index = max(0, self.selected_interface - visible_rows + 1)
        start_index = min(start_index, max(len(interfaces) - visible_rows, 0))

        for row, interface in enumerate(interfaces[start_index:start_index + visible_rows], start=2):
            actual_index = start_index + row - 2
            prefix = "> " if actual_index == self.selected_interface else "  "
            attr = self.modal_attr if actual_index == self.selected_interface else self.normal_attr
            self._safe_addnstr(modal, row, 2, f"{prefix}{interface}", max(width - 4, 1), attr)

        modal.refresh()

    def _compose_stacked(self, canvas, height, width):
        stats_height = max(8, min(10, height // 4))
        alerts_height = max(7, min(9, height // 4))
        log_height = height - stats_height - alerts_height

        if log_height < 4:
            self._compose_logs(canvas, 0, 0, height, width)
            return

        self._compose_logs(canvas, 0, 0, log_height, width)
        self._compose_stats(canvas, log_height, 0, stats_height, width)
        self._compose_alerts(canvas, log_height + stats_height, 0, alerts_height, width)

    def _compose_logs(self, canvas, start_y, start_x, height, width):
        self._draw_text_box(canvas, start_y, start_x, height, width, " Connections ")
        usable_height = max(height - 2, 1)

        with self.lock:
            lines = list(self.log_lines)[:usable_height]

        if not lines:
            self._write_text(canvas, start_y + 1, start_x + 1, "Waiting for packets...", width - 2)
            return

        for index, line in enumerate(lines, start=1):
            if index >= height - 1:
                break
            self._write_text(canvas, start_y + index, start_x + 1, line, width - 2)

    def _compose_stats(self, canvas, start_y, start_x, height, width):
        self._draw_text_box(canvas, start_y, start_x, height, width, " Stats ")
        stats = self.stats.snapshot()
        top_sources = self.stats.top_sources_data(limit=max(height - 9, 1))

        lines = [
            f"Interface: {self.interface}",
            f"Total packets: {stats['total_packets']}",
            f"TCP packets:   {stats['tcp_packets']}",
            f"UDP packets:   {stats['udp_packets']}",
            "",
            "Top source IPs:"
        ]

        for ip, count in top_sources:
            lines.append(f"{ip} [{count}]")

        for index, line in enumerate(lines, start=1):
            if index >= height - 1:
                break
            self._write_text(canvas, start_y + index, start_x + 1, line, width - 2)

        self._write_text(
            canvas,
            start_y + height - 2,
            start_x + 1,
            "Press q to quit | s save | w interface",
            width - 2
        )

    def _compose_alerts(self, canvas, start_y, start_x, height, width):
        self._draw_text_box(canvas, start_y, start_x, height, width, " Alerts ")
        usable_height = max(height - 2, 1)

        with self.lock:
            alerts = list(self.alert_lines)[:usable_height]

        if not alerts:
            self._write_text(canvas, start_y + 1, start_x + 1, "No alerts yet", width - 2)
            return

        for index, line in enumerate(alerts, start=1):
            if index >= height - 1:
                break
            self._write_text(canvas, start_y + index, start_x + 1, line, width - 2)

    def _draw_text_box(self, canvas, start_y, start_x, height, width, title):
        if height < 3 or width < 4:
            return

        last_y = start_y + height - 1
        last_x = start_x + width - 1

        canvas[start_y][start_x] = "+"
        canvas[start_y][last_x] = "+"
        canvas[last_y][start_x] = "+"
        canvas[last_y][last_x] = "+"

        for x in range(start_x + 1, last_x):
            canvas[start_y][x] = "-"
            canvas[last_y][x] = "-"

        for y in range(start_y + 1, last_y):
            canvas[y][start_x] = "|"
            canvas[y][last_x] = "|"

        self._write_text(canvas, start_y, start_x + 2, title, width - 4)

    def _write_text(self, canvas, y, x, text, limit):
        if y < 0 or y >= len(canvas) or x >= len(canvas[y]) or limit <= 0:
            return

        row = canvas[y]
        for index, char in enumerate(text[:limit]):
            if x + index >= len(row):
                break
            row[x + index] = char
