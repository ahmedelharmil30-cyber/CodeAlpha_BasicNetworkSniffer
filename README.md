# NetworkSniffer - Network Intrusion Detection System

A modern Python GUI for live network packet capture, protocol analysis, and traffic inspection.

## 🚀 What it does

- Captures live traffic using `scapy`
- Displays packet details in a real-time table
- Classifies protocols across TCP/UDP, ICMP, ARP, DNS, HTTP, HTTPS, SSH, FTP, SMTP, and more
- Offers interface selection with Windows-friendly adapter names
- Supports dark/light themes and instant UI refresh
- Saves and loads capture sessions as PCAP or JSON

## ✨ Highlights

- Friendly adapter names for Windows network interfaces
- Port-based detection for many common protocols
- Packet stats and protocol distribution charts
- Packet detail viewer with layered packet breakdown
- Export packets to PCAP, JSON, or text

## 🛠️ Installation

1. Install Python 3.8 or newer.
2. Install dependencies:

```bash
python -m pip install -r requirements.txt
```

> If your system already includes `tkinter`, no extra GUI dependency is required.

## ▶️ Usage

Launch the application:

```bash
python nids.py
```

Then:

1. Select a network interface from the drop-down
2. Click **Start Capture**
3. Filter packets by protocol, source/destination, or keyword
4. Click a packet to view decoded details

## 📁 Save / Load Capture

- Save captured packets as `PCAP` or `JSON`
- Reload saved traffic for offline analysis
- Export individual packet details to plain text

## ⚙️ Customization

- `MAX_PAYLOAD_STORE` controls how much raw packet payload is kept in memory
- `MAX_PAYLOAD_DISPLAY` controls how much payload is shown in the UI

## ❗ Notes

- Scapy may require administrator/root permissions for packet capture
- On Windows, the app uses PowerShell to resolve adapter names
- `tkinter` is bundled with most Python distributions, so additional installation is usually not needed

## 🧭 Supported Protocols

Includes built-in recognition for:

- `TCP`, `UDP`, `ICMP`, `ICMPv6`, `ARP`, `IP`, `IPv6`
- `DNS`, `HTTP`, `HTTPS`, `SSH`, `FTP`, `FTPS`, `SFTP`
- `SMTP`, `POP3`, `POP3S`, `IMAP`, `IMAPS`, `TELNET`
- `RDP`, `MYSQL`, `MSSQL`, `LDAP`, `LDAPS`, `SMB`, `NFS`
- `DHCP`, `DHCPv6`, `TFTP`, `SNMP`, `SIP`, `RTP`, `RTSP`, `RTMP`
- `MQTT`, `AMQP`, `RADIUS`, `KERBEROS`, `BGP`, `OSPF`, `RIP`, `VXLAN`, `IPSEC`

## 🧩 Notes for Developers

- Main application code is in `nids.py`
- Adjust live theming and UI layout in the same file
- Protocol mapping is defined in `COMMON_PORT_PROTOCOLS`

## 📦 Dependencies

- `scapy`
- `matplotlib`
- `tkinter` (standard library GUI module)
