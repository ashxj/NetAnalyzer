# NetAnalyzer

NetAnalyzer is a terminal-based network monitoring tool built with Python, Scapy, and a custom curses TUI.
It captures live traffic, resolves source countries via GeoLite2, tracks basic traffic statistics, and raises simple alerts for suspicious patterns such as port scanning and repeated SSH connection attempts.  
![alt text](https://raw.githubusercontent.com/ashxj/NetAnalyzer/refs/heads/main/screenshots/preview.png)

## Features

- Live packet capture from a selected network interface
- Real-time TUI with separate panels for connections, stats, and alerts
- GeoIP country lookup for source IP addresses
- Basic protocol statistics for total, TCP, and UDP packets
- Top source IP aggregation
- Port scan detection based on unique destination ports per source
- SSH brute-force detection based on repeated traffic to port `22`
- Scrollable `Connections` and `Alerts` panels
- Runtime interface switching from inside the TUI
- Plain-text log export with stats, alerts, and connection history

## Interface Overview

The TUI is split into three main areas:

- `Connections`: live traffic log with source IP, country, destination IP, and destination port
- `Stats`: interface name, packet counters, and top source IPs
- `Alerts`: suspicious activity detected by the analyzer

The bottom status bar shows the application name, version, and active keybindings.

## Detection Logic

NetAnalyzer currently uses simple heuristic rules:

- Port scan alert: triggered when one source IP targets more than `20` unique destination ports
- SSH brute-force alert: triggered when one source IP generates more than `15` packets toward destination port `22`

These thresholds are intentionally simple and are best treated as lightweight indicators, not production-grade IDS rules.

## Project Layout

| Path | Purpose |
| --- | --- |
| `src/netanalyzer/main.py` | Application entry point and runtime wiring |
| `src/netanalyzer/capture.py` | Async packet capture using Scapy |
| `src/netanalyzer/parser.py` | Packet parsing for IP/TCP/UDP metadata |
| `src/netanalyzer/analyzer.py` | Detection logic for alerts |
| `src/netanalyzer/stats.py` | Traffic counters and top-source aggregation |
| `src/netanalyzer/geoip.py` | MaxMind GeoLite2 country lookup |
| `src/netanalyzer/tui.py` | Full curses-based terminal UI |
| `src/netanalyzer/data/` | GeoLite database storage |

## Requirements

- Python 3.12+
- Linux
- Root privileges or Linux capabilities for raw packet capture
- A network interface available to Scapy

Python packages used by the project:

- `scapy`
- `geoip2`
- `colorama` (optional; the TUI works without it)

## Installation

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install scapy geoip2 colorama
```

## GeoLite Database

Download GeoLite2-Country.mmdb from MaxMind
and place it into /data directory

In this repository, that file is expected at:

```text
src/netanalyzer/data/GeoLite2-Country.mmdb
```

## Packet Capture Permissions

You can run NetAnalyzer as `root`, but a cleaner option is to grant the Python interpreter the required capabilities:

```bash
sudo setcap 'cap_net_raw,cap_net_admin=eip' "$(readlink -f "$(command -v python3)")"
```

Verify:

```bash
getcap "$(readlink -f "$(command -v python3)")"
```

If you use a virtual environment, apply capabilities to the interpreter inside `.venv` instead.

## Running the Application

From the project root:

```bash
PYTHONPATH=src .venv/bin/python -m netanalyzer.main
```

Or from inside `src/`:

```bash
../.venv/bin/python -m netanalyzer.main
```

The default startup interface is currently hardcoded as `wlan0`, but you can switch interfaces at runtime from the TUI.

## Keybindings

| Key | Action | Description |
| --- | --- | --- |
| `q` | Quit | Exit the TUI and stop packet capture |
| `s` | Save log | Export a plain-text `.log` file with stats, alerts, and connections |
| `w` | Switch interface | Open a modal window and choose another network interface |
| `c` | Clear logs | Clear both `Connections` and `Alerts` panels |
| `Tab` | Change focus | Switch scroll focus between `Connections` and `Alerts` |
| `j` / `Down` | Scroll down | Move the active panel through older entries |
| `k` / `Up` | Scroll up | Move the active panel back toward newer entries |
| `PgDn` | Page down | Scroll the active panel by one page toward older entries |
| `PgUp` | Page up | Scroll the active panel by one page toward newer entries |
| `g` | Jump to history | Move the active panel to the oldest available entries |
| `G` | Jump to live end | Move the active panel back to the newest visible range |
| `l` | Live mode | Reset scroll and follow the newest events again |
| `Enter` | Confirm selection | Confirm the selected interface in the switch modal |
| `Esc` | Close modal | Close the interface switch modal without changing interface |

## Log Output

Saved log files are plain text and contain:

- Save timestamp
- Active interface
- Packet statistics
- Top source IPs
- Alerts
- Connection history

This makes exported logs readable outside the TUI and suitable for quick review or sharing.

## Visual Cues

- `[INFO]` messages are shown in green
- `[WARNING]` messages are shown in yellow
- `[ALERT]` messages are shown in red
- The active scrollable panel title is highlighted

## Notes

- The current detection logic is stateful and accumulates counts over time.
- GeoIP resolution is country-only.
- The application is Linux-oriented and expects a terminal with `curses` support.
- Very small terminal sizes will degrade the layout.

## Future Improvements

- Configurable interfaces and thresholds from CLI arguments
- Time-window-based alerting to reduce false positives
- Dedicated alert severity levels
- Persistent configuration and dependency metadata
- Automated tests for parser, analyzer, and UI state transitions
