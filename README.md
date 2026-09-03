# Pakcha - Network Packet Capture

Pakcha is a desktop packet capture application for Windows, built with Python, Tkinter, and Scapy. It provides a graphical interface for capturing live network traffic, inspecting individual packets, filtering results, and saving or loading capture files in PCAP format.

## Features

- Live packet capture from any available network interface
- Interface list with description, IPv4 address, and index, refreshable on demand
- Start and stop capture at any time without closing the application
- Scrollable packet table showing number, timestamp, source, destination, protocol, length, and summary info
- Color-coded rows by protocol (TCP, UDP, ARP, DNS, ICMP) and alternating row shading for readability
- Detailed packet inspector showing a full field-by-field breakdown of the selected packet
- Text-based filter bar with support for protocol names and simple query syntax
- Open existing `.pcap`, `.pcapng`, or `.cap` files for offline review
- Save the current capture to a `.pcap` file
- Clear the current packet list and start fresh
- Status bar with live feedback on capture state and packet counts

## Requirements

- Windows operating system
- [Npcap](https://npcap.com/) installed (required by Scapy for live packet capture on Windows)
- Python 3.8 or later
- The following Python packages:
  - `scapy`

Install the dependency with:

```
pip install scapy
```

Administrator privileges are typically required to capture packets on Windows.

## Running the Application

Run the script from a terminal with sufficient privileges:

```
python pakcha.py
```

The main window opens with a list of detected network interfaces, a capture control bar, a filter field, a packet table, and a packet detail pane.

## Usage

### Selecting an Interface

Choose a network interface from the dropdown at the top of the window. Use **Refresh** to reload the list of available interfaces if a device has changed since the application started. If a Realtek or other recognizable Wi-Fi adapter is detected, it is selected automatically on first load.

### Capturing Packets

- Click **Start Capture** to begin sniffing on the selected interface. The interface selector and file controls are disabled while a capture is running.
- Click **Stop Capture** to end the session. Capture is stopped on a background thread so the interface remains responsive.
- Click **Clear** to remove all packets from the current session (only available when not capturing).

### Viewing Packet Details

Select any row in the packet table to display a full breakdown of that packet in the details pane below, including a summary header (number, time, source, destination, protocol, length, info) followed by the complete Scapy field dump.

### Filtering

Type into the **Filter** field to narrow the packet table. Filtering is applied live as you type and supports:

| Filter syntax | Description |
|---|---|
| `tcp`, `udp`, `icmp`, `arp`, `dns`, `ip`, `ipv6` | Show only packets of the given protocol |
| `host <address>` | Show packets where source or destination matches the address |
| `src <address>` | Show packets with the given source address |
| `dst <address>` | Show packets with the given destination address |
| `port <number>` | Show TCP/UDP packets using the given source or destination port |
| Any other text | Generic case-insensitive search across all visible columns |

Clearing the filter field shows all captured packets again.

### Working with PCAP Files

- **File > Open PCAP...** (`Ctrl+O`): Load packets from an existing capture file. This replaces the current packet list.
- **File > Save As PCAP...** (`Ctrl+Shift+S` or `Ctrl+S`): Save all currently listed packets to a `.pcap` file.

Both operations are disabled while a live capture is in progress.

## Notes

- Packet capture requires the application to run with the necessary permissions (typically Administrator on Windows) and requires Npcap to be installed.
- The packet table updates in near real time; incoming packets are queued and flushed to the interface in small batches to keep the UI responsive during high-traffic captures.
- Closing the window while a capture is active stops the underlying sniffer in the background before the application exits.

## Disclaimer

This tool captures network traffic on the interfaces you select. Only use it on networks and systems you own or have explicit authorization to monitor.
