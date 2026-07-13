
"""
NetworkSniffer - Professional Network Intrusion Detection System
Modern GUI with sidebar navigation and advanced analytics
"""

import os
import re
import sys
import json
import subprocess
import logging
from datetime import datetime
from collections import defaultdict, Counter

try:
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, Raw, ARP, Ether, get_if_list, DNS
except Exception:
    try:
        from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, Raw, ARP, Ether, get_if_list
        DNS = None
    except Exception:
        AsyncSniffer = None
        get_if_list = None
        DNS = None

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'networksniffer_alerts.log')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')])

sniffer = None
sniffer_running = False
app = None

# Professional color palette - Enhanced
PRIMARY = '#2563eb'
PRIMARY_DARK = '#1d4ed8'
PRIMARY_LIGHT = '#3b82f6'
PRIMARY_HOVER = '#1e40af'
SECONDARY = '#10b981'
SECONDARY_DARK = '#059669'
ACCENT = '#f59e0b'
ACCENT_DARK = '#d97706'
DANGER = '#ef4444'
PURPLE = '#8b5cf6'
CYAN = '#06b6d4'

DARK_BG = '#0f1419'
DARK_SIDEBAR = '#111827'
DARK_CARD = '#1e293b'
DARK_CARD_ALT = '#273449'
DARK_BORDER = '#374151'
DARK_TEXT = '#f8fafc'
DARK_TEXT_SECONDARY = '#94a3b8'
DARK_INPUT = '#111827'

LIGHT_BG = '#f8fafc'
LIGHT_SIDEBAR = '#eff6ff'
LIGHT_CARD = '#ffffff'
LIGHT_CARD_ALT = '#f1f5f9'
LIGHT_BORDER = '#cbd5e1'
LIGHT_TEXT = '#0f172a'
LIGHT_TEXT_SECONDARY = '#475569'
LIGHT_INPUT = '#ffffff'

PROTOCOL_OPTIONS = [
    'All', 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'IP', 'IPv6', 'DNS', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'FTPS',
    'SFTP', 'SMTP', 'POP3', 'POP3S', 'IMAP', 'IMAPS', 'TELNET', 'RDP', 'MYSQL', 'MSSQL', 'LDAP', 'LDAPS',
    'SMB', 'NFS', 'DHCP', 'DHCPv6', 'TFTP', 'SNMP', 'SIP', 'RTP', 'RTSP', 'RTMP', 'MQTT', 'AMQP', 'RADIUS',
    'KERBEROS', 'BGP', 'OSPF', 'RIP', 'VXLAN', 'IPSEC', 'OTHER'
]
COMMON_PORT_PROTOCOLS = {
    20: 'FTP', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
    137: 'SMB', 138: 'SMB', 139: 'SMB', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP',
    179: 'BGP', 189: 'APTP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTP',
    514: 'SYSLOG', 520: 'RIP', 546: 'DHCPv6', 547: 'DHCPv6', 554: 'RTSP',
    587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    1434: 'MSSQL', 1701: 'L2TP', 1723: 'PPTP', 2049: 'NFS', 3306: 'MYSQL',
    3389: 'RDP', 3478: 'STUN', 3689: 'DAAP', 5060: 'SIP', 5061: 'SIP',
    5222: 'XMPP', 5432: 'POSTGRES', 5672: 'AMQP', 5671: 'AMQP', 5900: 'VNC',
    6379: 'REDIS', 6667: 'IRC', 6881: 'BITTORRENT', 8080: 'HTTP', 8443: 'HTTPS',
    9000: 'WEBMIN', 11211: 'MEMCACHED', 4789: 'VXLAN', 500: 'IPSEC', 4500: 'IPSEC',
    88: 'KERBEROS', 2600: 'Z39.50'
}
COLORS = [
    PRIMARY_LIGHT, SECONDARY, ACCENT, DANGER, PURPLE, CYAN, '#ec4899', '#f97316', '#22c55e', '#eab308',
    '#8b5cf6', '#14b8a6', '#0ea5e9', '#fb7185', '#a855f7', '#f43f5e', '#84cc16', '#38bdf8', '#c026d3',
    '#facc15', '#7c3aed', '#0f766e', '#9333ea', '#dc2626', '#0ea5e9', '#f59e0b', '#10b981', '#8b5cf6',
    '#0f766e', '#f97316', '#0ea5e9', '#f43f5e', '#2dd4bf', '#fb7185', '#22c55e', '#ef4444', '#f97316',
    '#14b8a6', '#8b5cf6', '#0ea5e9', '#fb7185', '#f97316', '#22c55e', '#ec4899'
]

# Limits for storing and displaying payloads to avoid huge memory usage
MAX_PAYLOAD_STORE = 1024  # bytes to keep in memory per packet
MAX_PAYLOAD_DISPLAY = 180  # characters to show in the UI


def format_payload(payload_bytes, max_len=180):
    if not payload_bytes:
        return ''
    try:
        payload = payload_bytes.decode('utf-8', errors='replace')
    except Exception:
        payload = ''.join((chr(b) if 32 <= b < 127 else '.') for b in payload_bytes)
    if len(payload) > max_len:
        return payload[:max_len] + '...'
    return payload


def format_payload_hex(payload_bytes):
    if not payload_bytes:
        return ''
    hex_pairs = [f'{b:02X}' for b in payload_bytes]
    lines = [' '.join(hex_pairs[i:i+16]) for i in range(0, len(hex_pairs), 16)]
    return '\n'.join(lines)


def format_hexdump(payload_bytes, width=16):
    if not payload_bytes:
        return ''
    lines = []
    for i in range(0, len(payload_bytes), width):
        chunk = payload_bytes[i:i+width]
        hex_pairs = ' '.join(f'{b:02x}' for b in chunk)
        # pad hex area to align ASCII column
        pad_len = width * 3 - 1
        hex_area = hex_pairs.ljust(pad_len)
        ascii_part = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        lines.append(f'{i:04x}  {hex_area}  |{ascii_part}|')
    return '\n'.join(lines)


WINDOWS_ADAPTER_MAP = None


def load_windows_adapter_map():
    global WINDOWS_ADAPTER_MAP
    if WINDOWS_ADAPTER_MAP is not None:
        return WINDOWS_ADAPTER_MAP

    WINDOWS_ADAPTER_MAP = {}
    if sys.platform != 'win32':
        return WINDOWS_ADAPTER_MAP

    commands = [
        [
            'powershell',
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-Command',
            'Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,NetConnectionID | ConvertTo-Json -Compress'
        ],
        [
            'powershell',
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-Command',
            'Get-CimInstance -ClassName Win32_NetworkAdapter | Select-Object NetConnectionID,Description,GUID | ConvertTo-Json -Compress'
        ],
        [
            'powershell',
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-Command',
            'Get-WmiObject Win32_NetworkAdapter | Select-Object NetConnectionID,Description,GUID | ConvertTo-Json -Compress'
        ]
    ]

    def parse_json_entries(output, guid_key, name_keys):
        try:
            data = json.loads(output)
        except Exception:
            return
        if isinstance(data, dict):
            data = [data]
        for entry in data:
            guid = str(entry.get(guid_key, '')).strip().strip('{}').upper()
            for key in name_keys:
                friendly = entry.get(key)
                if friendly:
                    friendly = str(friendly).strip()
                    if friendly:
                        break
            else:
                friendly = ''
            if guid and friendly:
                WINDOWS_ADAPTER_MAP[guid] = friendly

    for cmd in commands:
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=True,
            )
            if completed.stdout:
                if 'InterfaceGuid' in cmd[-1]:
                    parse_json_entries(completed.stdout, 'InterfaceGuid', ['NetConnectionID', 'Name', 'InterfaceDescription'])
                else:
                    parse_json_entries(completed.stdout, 'GUID', ['NetConnectionID', 'Description'])
                if WINDOWS_ADAPTER_MAP:
                    break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            continue

    if not WINDOWS_ADAPTER_MAP:
        try:
            cmd = [
                'powershell',
                '-NoProfile',
                '-ExecutionPolicy',
                'Bypass',
                '-Command',
                'Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceGuid,NetConnectionID | Format-List | Out-String'
            ]
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=True,
            )
            output = completed.stdout
            entries = re.findall(
                r'Name\s*:\s*(.*?)\r?\n.*?InterfaceDescription\s*:\s*(.*?)\r?\n.*?NetConnectionID\s*:\s*(.*?)\r?\n.*?InterfaceGuid\s*:\s*(.*?)\r?\n',
                output,
                re.IGNORECASE | re.DOTALL,
            )
            for name, description, connection_id, guid in entries:
                clean_guid = str(guid).strip().strip('{}').upper()
                friendly = connection_id.strip() or name.strip() or description.strip()
                if clean_guid and friendly:
                    WINDOWS_ADAPTER_MAP[clean_guid] = friendly
        except Exception:
            pass

    return WINDOWS_ADAPTER_MAP


def format_packet(packet):
    proto = 'OTHER'
    src = dst = ''
    src_mac = dst_mac = ''
    src_port = dst_port = ''
    info = ''
    raw_text = ''
    raw_hex = ''

    if Ether is not None and Ether in packet:
        try:
            ether = packet[Ether]
            src_mac = ether.src
            dst_mac = ether.dst
        except Exception:
            pass

    if IP is not None and IP in packet:
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        if TCP is not None and TCP in packet:
            proto = 'TCP'
            tcp = packet[TCP]
            src_port = str(tcp.sport)
            dst_port = str(tcp.dport)
            info = f'{src_port}->{dst_port}'
        elif UDP is not None and UDP in packet:
            proto = 'UDP'
            udp = packet[UDP]
            src_port = str(udp.sport)
            dst_port = str(udp.dport)
            info = f'{src_port}->{dst_port}'
        elif ICMP is not None and ICMP in packet:
            proto = 'ICMP'
        else:
            proto = 'IP'
    elif DNS is not None and DNS in packet:
        # DNS over UDP/TCP can appear; prefer to mark as DNS protocol
        proto = 'DNS'
    elif IPv6 is not None and IPv6 in packet:
        ipv6 = packet[IPv6]
        src = ipv6.src
        dst = ipv6.dst
        if TCP is not None and TCP in packet:
            proto = 'TCP'
            tcp = packet[TCP]
            src_port = str(tcp.sport)
            dst_port = str(tcp.dport)
            info = f'{src_port}->{dst_port}'
        elif UDP is not None and UDP in packet:
            proto = 'UDP'
            udp = packet[UDP]
            src_port = str(udp.sport)
            dst_port = str(udp.dport)
            info = f'{src_port}->{dst_port}'
        elif ICMP is not None and ICMP in packet:
            proto = 'ICMP'
        else:
            proto = 'IPv6'
    elif ARP is not None and ARP in packet:
        proto = 'ARP'
        try:
            arp = packet[ARP]
            src = arp.psrc
            dst = arp.pdst
            info = f'OP={arp.op}'
        except Exception:
            pass
    else:
        proto = packet.__class__.__name__

    payload_bytes = b''
    if Raw is not None and Raw in packet:
        try:
            payload_bytes = bytes(packet[Raw].load)
        except Exception:
            payload_bytes = b''

        # Keep only a bounded amount of payload in memory to avoid large UI items
        truncated = False
        original_len = len(payload_bytes)
        if original_len > MAX_PAYLOAD_STORE:
            truncated = True
            store_bytes = payload_bytes[:MAX_PAYLOAD_STORE]
        else:
            store_bytes = payload_bytes

        raw_text = format_payload(store_bytes, max_len=MAX_PAYLOAD_DISPLAY)
        raw_hex = format_payload_hex(store_bytes)
        if truncated:
            diff = original_len - len(store_bytes)
            raw_text = raw_text + f"\n... (truncated {diff} bytes)"
            raw_hex = raw_hex + f"\n... (truncated {diff} bytes)"

    # Try to extract DNS query name if present and detect service-specific protocols
    dns_name = ''
    try:
        if DNS is not None and DNS in packet:
            dns_layer = packet[DNS]
            if getattr(dns_layer, 'qdcount', 0) > 0 and hasattr(dns_layer, 'qd'):
                qd = dns_layer.qd
                qname = getattr(qd, 'qname', None)
                if qname:
                    try:
                        dns_name = qname.decode('utf-8').rstrip('.')
                    except Exception:
                        dns_name = str(qname)
                    if dns_name:
                        info = (info + ' ' + f'DNS:{dns_name}').strip()
            proto = 'DNS'
    except Exception:
        dns_name = ''

    # Detect application-level protocols by common ports when available
    try:
        if TCP is not None and TCP in packet:
            tcp = packet[TCP]
            sport = int(getattr(tcp, 'sport', 0))
            dport = int(getattr(tcp, 'dport', 0))
            proto = COMMON_PORT_PROTOCOLS.get(sport) or COMMON_PORT_PROTOCOLS.get(dport) or proto
            if proto == 'OTHER':
                proto = 'TCP'
        elif UDP is not None and UDP in packet:
            udp = packet[UDP]
            sport = int(getattr(udp, 'sport', 0))
            dport = int(getattr(udp, 'dport', 0))
            proto = COMMON_PORT_PROTOCOLS.get(sport) or COMMON_PORT_PROTOCOLS.get(dport) or proto
            if proto == 'OTHER':
                proto = 'UDP'
    except Exception:
        pass

    # Try to determine full packet length
    pkt_len = None
    try:
        pkt_len = len(bytes(packet))
    except Exception:
        try:
            pkt_len = int(packet.len) if hasattr(packet, 'len') else None
        except Exception:
            pkt_len = None

    return {
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src': src,
        'dst': dst,
        'src_mac': src_mac,
        'dst_mac': dst_mac,
        'src_port': src_port,
        'dst_port': dst_port,
        'proto': proto,
        'info': info,
        'raw': raw_text,
        'raw_hex': raw_hex,
        'length': pkt_len if pkt_len is not None else 0,
        'payload_len': len(payload_bytes) if payload_bytes is not None else 0,
        'dns': dns_name,
        'raw_packet': packet,
    }


def packet_handler(packet, iface=None):
    global app
    # compatibility: function may be called with (packet, iface)
    if isinstance(packet, tuple) and len(packet) >= 2:
        packet, iface = packet[0], packet[1]
    pkt = format_packet(packet)
    if iface is not None:
        pkt['iface'] = iface
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as log_file:
            log_file.write(f"{pkt['time']} | {pkt['proto']} | {pkt['src']} -> {pkt['dst']} | {pkt['info']}\n")
    except Exception:
        pass

    if app is not None:
        def insert_packet():
            if app is None:
                return
            item_id = f'pkt_{app.packet_sequence}'
            app.packet_sequence += 1
            app.packet_items[item_id] = pkt

            # Update statistics and insert record
            app.add_packet_record(pkt)
            try:
                app.total_bytes += int(pkt.get('length', 0) or 0)
                if hasattr(app, 'sidebar_bytes'):
                    app.sidebar_bytes.config(text=f'Bytes: {app.total_bytes:,}')
            except Exception:
                pass
            if len(app.packet_items) > app.max_packets:
                # remove oldest from both tree and packet_items; tree may not exist
                try:
                    if hasattr(app, 'tree') and app.tree.winfo_exists():
                        oldest = app.tree.get_children()[0]
                        app.tree.delete(oldest)
                        app.packet_items.pop(oldest, None)
                    else:
                        # remove arbitrary oldest key
                        oldest_key = next(iter(app.packet_items))
                        app.packet_items.pop(oldest_key, None)
                except Exception:
                    try:
                        oldest_key = next(iter(app.packet_items))
                        app.packet_items.pop(oldest_key, None)
                    except Exception:
                        pass
            app.packet_count += 1
            app.update_status()

        try:
            app.root.after(0, insert_packet)
        except Exception:
            pass


def format_interface_display(name):
    if not name:
        return name

    # Windows NPF adapter GUIDs -> try to map to friendly names
    npf_match = re.search(r'(?i)^[\\]+device[\\]+npf_\{?([0-9A-Fa-f-]{36})\}?$', name)
    if npf_match:
        guid = npf_match.group(1).upper()
        adapter_map = load_windows_adapter_map()
        if guid in adapter_map:
            return adapter_map[guid]
        # Fallback: return a friendly label instead of a raw GUID when possible
        return f'Network PC ({guid[:8]})'

    # Normalize loopback name to a friendly label
    if re.search(r'(?i)^\\device\\npf_loopback$', name):
        return 'Loopback'

    return name


def list_interfaces():
    if get_if_list is None:
        return []
    try:
        raw = get_if_list()
        interfaces = []
        seen = set()
        display_count = {}
        for iface in raw:
            if not iface:
                continue
            if iface in seen:
                continue
            seen.add(iface)
            display_name = format_interface_display(iface)
            if display_name is None:
                continue
            if display_name in display_count:
                display_count[display_name] += 1
                # Append a short suffix from the raw interface string to disambiguate
                short_id = iface[-8:]
                suffix = f' ({short_id})'
                display_name = f'{display_name}{suffix}'
            else:
                display_count[display_name] = 1
            interfaces.append((display_name, iface))
        return interfaces
    except Exception:
        return []


class NetworkSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('NetworkSniffer - Network Intrusion Detection System')
        self.root.geometry('1600x900')
        self.root.minsize(1400, 800)

        self.dark_theme = True
        self.packet_items = {}
        self.packet_sequence = 0
        self.packet_count = 0
        self.max_packets = 2000
        self.protocol_stats = Counter()
        self.ip_stats = defaultdict(int)
        self.current_view = 'dashboard'

        self.style = ttk.Style()
        self.configure_custom_style()
        self.root.configure(bg=DARK_BG if self.dark_theme else LIGHT_BG)

        # Main layout
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)

        self.build_sidebar(main_container)
        self.build_main_content(main_container)
        self.build_status_bar()

        self.refresh_interfaces()
        # load persisted UI config (sash position)
        self.config_file = os.path.join(BASE_DIR, 'networksniffer_config.json')
        self.ui_config = {}
        try:
            if os.path.isfile(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as cf:
                    self.ui_config = json.load(cf)
        except Exception:
            self.ui_config = {}
        # track total captured bytes
        self.total_bytes = 0
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        # Bind resize to adjust column widths automatically
        try:
            self.root.bind('<Configure>', self.on_resize)
        except Exception:
            pass
        # Periodically refresh the interface list (10s)
        try:
            self.root.after(10000, self.periodic_refresh_interfaces)
        except Exception:
            pass
        self.update_loop()

    def on_resize(self, event=None):
        # Responsive column resizing for the packet table
        try:
            if not hasattr(self, 'tree'):
                return
            # weights for proportional sizing
            weights = {
                'Time': 2,
                'Size': 1,
                'Source IP': 2,
                'Dest IP': 2,
                'Protocol': 1,
                'Port Info': 3,
            }
            total_weight = sum(weights.values())
            tree_width = self.tree.winfo_width()
            if tree_width <= 50:
                return
            # subtract estimated scrollbar width
            scrollbar_width = 20
            available = max(100, tree_width - scrollbar_width)
            for col, wt in weights.items():
                try:
                    col_width = max(60, int(available * wt / total_weight))
                    self.tree.column(col, width=col_width)
                except Exception:
                    pass
            # adjust details text height based on remaining content area
            if hasattr(self, 'layer_text') and hasattr(self, 'content_frame'):
                try:
                    # approximate rows from content_frame height
                    h = self.content_frame.winfo_height()
                    rows = max(6, int(h / 40))
                    try:
                        self.layer_text.config(height=rows)
                        if hasattr(self, 'details_text'):
                            self.details_text.config(height=rows)
                    except Exception:
                        pass
                except Exception:
                    pass
        except Exception:
            pass

    def configure_custom_style(self):
        self.style.theme_use('clam')

        # Frame styles
        self.style.configure('Sidebar.TFrame', background=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR, relief='flat', borderwidth=0)
        self.style.configure('Content.TFrame', background=DARK_BG if self.dark_theme else LIGHT_BG, relief='flat', borderwidth=0)
        self.style.configure('Card.TFrame', background=DARK_CARD if self.dark_theme else LIGHT_CARD, relief='flat', borderwidth=0)

        # Label styles
        self.style.configure('SidebarTitle.TLabel', background=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR, foreground=DARK_TEXT if self.dark_theme else LIGHT_TEXT, font=('Segoe UI', 14, 'bold'))
        self.style.configure('TLabel', background=DARK_BG if self.dark_theme else LIGHT_BG, foreground=DARK_TEXT if self.dark_theme else LIGHT_TEXT, font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', background=DARK_BG if self.dark_theme else LIGHT_BG, foreground=DARK_TEXT if self.dark_theme else LIGHT_TEXT, font=('Segoe UI', 18, 'bold'))
        self.style.configure('Subtitle.TLabel', background=DARK_BG if self.dark_theme else LIGHT_BG, foreground=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY, font=('Segoe UI', 10))

        # Button styles
        self.style.configure('Primary.TButton', background=PRIMARY, foreground='#ffffff', font=('Segoe UI', 10, 'bold'), padding=10, relief='flat', borderwidth=0)
        self.style.map('Primary.TButton', 
                      background=[('active', PRIMARY_DARK), ('pressed', PRIMARY_HOVER), ('disabled', '#6b7280')],
                      foreground=[('disabled', LIGHT_TEXT_SECONDARY)])

        self.style.configure('Secondary.TButton', background=DARK_CARD_ALT if self.dark_theme else LIGHT_CARD_ALT, foreground=DARK_TEXT if self.dark_theme else LIGHT_TEXT, font=('Segoe UI', 10), padding=8, relief='flat', borderwidth=0)
        self.style.map('Secondary.TButton',
                      background=[('active', DARK_BORDER if self.dark_theme else LIGHT_BORDER), ('pressed', DARK_BORDER if self.dark_theme else DARK_TEXT_SECONDARY)],
                      foreground=[('active', DARK_TEXT if self.dark_theme else LIGHT_TEXT)])

        # Treeview styles
        self.style.configure('Treeview', background=DARK_CARD if self.dark_theme else LIGHT_CARD, fieldbackground=DARK_CARD if self.dark_theme else LIGHT_CARD, foreground=DARK_TEXT if self.dark_theme else LIGHT_TEXT, rowheight=26, font=('Segoe UI', 9))
        self.style.configure('Treeview.Heading', background=DARK_CARD_ALT if self.dark_theme else LIGHT_CARD_ALT, foreground=DARK_TEXT if self.dark_theme else LIGHT_TEXT, relief='flat', font=('Segoe UI', 10, 'bold'), padding=8, borderwidth=0)
        self.style.map('Treeview', background=[('selected', PRIMARY), ('focus', PRIMARY)], foreground=[('selected', '#ffffff'), ('focus', '#ffffff')])

        # Scrollbar styles
        self.style.configure('Vertical.TScrollbar', background=DARK_BORDER if self.dark_theme else LIGHT_BORDER, troughcolor=DARK_CARD if self.dark_theme else LIGHT_CARD_ALT, borderwidth=0, relief='flat')
        
        # Combobox styles (limited due to TTK limitations)
        self.style.configure('TCombobox', fieldbackground=DARK_INPUT if self.dark_theme else LIGHT_INPUT, background=DARK_CARD if self.dark_theme else LIGHT_CARD, foreground=DARK_TEXT if self.dark_theme else LIGHT_TEXT, font=('Segoe UI', 10))
        self.style.map('TCombobox', fieldbackground=[('focus', PRIMARY)], foreground=[('focus', '#ffffff')])

    def build_sidebar(self, parent):
        sidebar = tk.Frame(parent, bg=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR, width=240)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Logo frame
        logo_frame = tk.Frame(sidebar, bg=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR)
        logo_frame.pack(fill=tk.X, padx=16, pady=16)

        title_label = tk.Label(logo_frame, text='🛡️ NetworkSniffer', font=('Segoe UI', 14, 'bold'), 
                              bg=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR,
                              fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT)
        title_label.pack(anchor='w')
        
        subtitle_label = tk.Label(logo_frame, text='Network Sniffer', font=('Segoe UI', 9),
                                 bg=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR,
                                 fg=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
        subtitle_label.pack(anchor='w')

        # Navigation frame
        nav_frame = tk.Frame(sidebar, bg=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR)
        nav_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=16)

        self.nav_buttons = {}
        nav_items = [
            ('dashboard', '📊 Dashboard'),
            ('capture', '📡 Live Capture'),
            ('analyst', '🔍 Analyst'),
            ('alerts', '⚠️  Alerts'),
            ('settings', '⚙️  Settings'),
        ]

        for key, label in nav_items:
            btn = tk.Button(nav_frame, text=label, font=('Segoe UI', 10), anchor='w', padx=16, pady=12,
                           bg=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR, 
                           fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT,
                           activebackground=PRIMARY, activeforeground='#ffffff', 
                           bd=0, cursor='hand2', relief='flat', highlightthickness=0,
                           command=lambda k=key: self.switch_view(k))
            btn.pack(fill=tk.X, pady=4)
            self.nav_buttons[key] = btn

        # Info box at bottom
        info_frame = tk.Frame(sidebar, bg=DARK_CARD if self.dark_theme else LIGHT_CARD, relief='flat', highlightthickness=1, highlightbackground=DARK_BORDER if self.dark_theme else LIGHT_BORDER)
        info_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=8)

        info_inner = tk.Frame(info_frame, bg=DARK_CARD if self.dark_theme else LIGHT_CARD)
        info_inner.pack(fill=tk.BOTH, padx=12, pady=12)

        status_label = tk.Label(info_inner, text='Status', font=('Segoe UI', 9, 'bold'),
                               bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                               fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT)
        status_label.pack(anchor='w')
        
        self.sidebar_status = tk.Label(info_inner, text='● Ready', font=('Segoe UI', 9),
                                       bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                                       fg=SECONDARY)
        self.sidebar_status.pack(anchor='w', pady=(4, 0))

        packet_label = tk.Label(info_inner, text='Packets: 0', font=('Segoe UI', 9, 'bold'),
                               bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                               fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT)
        packet_label.pack(anchor='w', pady=(8, 0))
        
        self.sidebar_count = tk.Label(info_inner, text='TCP: 0 | UDP: 0', font=('Segoe UI', 8),
                                      bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                                      fg=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
        self.sidebar_count.pack(anchor='w')

        self.sidebar_bytes = tk.Label(info_inner, text='Bytes: 0', font=('Segoe UI', 8),
                          bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                          fg=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
        self.sidebar_bytes.pack(anchor='w', pady=(4, 0))

    def build_main_content(self, parent, initial_view=None):
        self.content_frame = tk.Frame(parent, bg=DARK_BG if self.dark_theme else LIGHT_BG)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.switch_view(initial_view or self.current_view or 'dashboard')

    def switch_view(self, view_name):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        for key, btn in self.nav_buttons.items():
            if key == view_name:
                btn.config(bg=PRIMARY, fg='#ffffff', relief='flat')
            else:
                btn.config(bg=DARK_SIDEBAR if self.dark_theme else LIGHT_SIDEBAR,
                          fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT, relief='flat')

        self.current_view = view_name

        if view_name == 'dashboard':
            self.build_dashboard()
        elif view_name == 'capture':
            self.build_capture_tab()
        elif view_name == 'analyst':
            self.build_analyst_tab()
        elif view_name == 'alerts':
            self.build_alerts_tab()
        elif view_name == 'settings':
            self.build_settings_tab()

    def build_dashboard(self):
        header = tk.Frame(self.content_frame, bg=DARK_BG if self.dark_theme else LIGHT_BG)
        header.pack(fill=tk.X, padx=20, pady=20)

        title = tk.Label(header, text='Dashboard', font=('Segoe UI', 18, 'bold'),
                        bg=DARK_BG if self.dark_theme else LIGHT_BG,
                        fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT)
        title.pack(anchor='w')
        
        subtitle = tk.Label(header, text='Real-time network monitoring and statistics', font=('Segoe UI', 10),
                           bg=DARK_BG if self.dark_theme else LIGHT_BG,
                           fg=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
        subtitle.pack(anchor='w', pady=(4, 0))

        content = tk.Frame(self.content_frame, bg=DARK_BG if self.dark_theme else LIGHT_BG)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        # Stats cards
        stats_frame = tk.Frame(content, bg=DARK_BG if self.dark_theme else LIGHT_BG)
        stats_frame.pack(fill=tk.X, pady=(0, 20))

        self.stat_cards = {}
        stats = [
            ('total', '📦 Total Packets', '0', ACCENT),
            ('tcp', '🔗 TCP', '0', PRIMARY),
            ('udp', '📨 UDP', '0', SECONDARY),
            ('icmp', '🔍 ICMP', '0', PURPLE),
        ]

        for key, title_text, value, color in stats:
            self.stat_cards[key] = self.create_stat_card(stats_frame, title_text, value, color)

        # Charts
        charts_frame = tk.Frame(content, bg=DARK_BG if self.dark_theme else LIGHT_BG)
        charts_frame.pack(fill=tk.BOTH, expand=True)

        left_chart = ttk.LabelFrame(charts_frame, text='Protocol Distribution', padding=16, style='Card.TFrame')
        left_chart.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        self.proto_figure = Figure(figsize=(6, 4), dpi=100, facecolor=DARK_CARD if self.dark_theme else LIGHT_CARD)
        self.proto_ax = self.proto_figure.add_subplot(111)
        self.proto_ax.tick_params(colors=DARK_TEXT if self.dark_theme else LIGHT_TEXT)
        self.proto_canvas = FigureCanvasTkAgg(self.proto_figure, left_chart)
        self.proto_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        right_chart = ttk.LabelFrame(charts_frame, text='Traffic Timeline', padding=16, style='Card.TFrame')
        right_chart.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        self.traffic_figure = Figure(figsize=(6, 4), dpi=100, facecolor=DARK_CARD if self.dark_theme else LIGHT_CARD)
        self.traffic_ax = self.traffic_figure.add_subplot(111)
        self.traffic_ax.tick_params(colors=DARK_TEXT if self.dark_theme else LIGHT_TEXT)
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_figure, right_chart)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def create_stat_card(self, parent, title_text, value, color):
        card = tk.Frame(parent, bg=DARK_CARD if self.dark_theme else LIGHT_CARD, relief='flat', 
                       highlightthickness=1, highlightbackground=DARK_BORDER if self.dark_theme else LIGHT_BORDER)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        color_bar = tk.Frame(card, bg=color, height=4)
        color_bar.pack(fill=tk.X)

        content = tk.Frame(card, bg=DARK_CARD if self.dark_theme else LIGHT_CARD)
        content.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        title_label = tk.Label(content, text=title_text, font=('Segoe UI', 10),
                              bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                              fg=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
        title_label.pack(anchor='w')

        value_label = tk.Label(content, text=value, font=('Segoe UI', 28, 'bold'),
                              bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                              fg=color)
        value_label.pack(anchor='w', pady=(8, 0))

        return value_label

    def build_capture_tab(self):
        header = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        header.pack(fill=tk.X)

        ttk.Label(header, text='Live Packet Capture', style='Title.TLabel').pack(anchor='w')
        ttk.Label(header, text='Monitor and analyze network traffic in real-time', style='Subtitle.TLabel').pack(anchor='w', pady=(4, 0))

        content = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        content.pack(fill=tk.BOTH, expand=True)

        # Controls
        ctrl_card = ttk.LabelFrame(content, text='Capture Controls', padding=16, style='Card.TFrame')
        ctrl_card.pack(fill=tk.X, pady=(0, 16))

        ctrl_inner = ttk.Frame(ctrl_card, style='Card.TFrame')
        ctrl_inner.pack(fill=tk.X)

        iface_frame = ttk.Frame(ctrl_inner, style='Card.TFrame')
        iface_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 16))

        ttk.Label(iface_frame, text='Interface:', font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 4))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(iface_frame, textvariable=self.iface_var, state='readonly', width=38, font=('Segoe UI', 10))
        self.iface_combo.pack(fill=tk.X)
        # Refresh interfaces when user clicks the dropdown
        try:
            self.iface_combo.bind('<Button-1>', lambda e: self.refresh_interfaces())
            self.iface_combo.bind('<FocusIn>', lambda e: self.refresh_interfaces())
            self.iface_combo.bind('<<ComboboxSelected>>', lambda e: self.on_iface_change())
        except Exception:
            pass

        btn_frame = ttk.Frame(ctrl_inner, style='Card.TFrame')
        btn_frame.pack(side=tk.RIGHT)

        ttk.Button(btn_frame, text='▶ Start', command=self.start_capture, style='Primary.TButton').pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='⏹ Stop', command=self.stop_capture, style='Secondary.TButton').pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='🔄 Refresh', command=self.refresh_interfaces, style='Secondary.TButton').pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='🗑️ Clear', command=self.clear_view, style='Secondary.TButton').pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='💾 Save Selected', command=self.save_selected, style='Secondary.TButton').pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='💾 Save All', command=self.save_capture, style='Secondary.TButton').pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='⬆️ Load', command=self.load_capture, style='Secondary.TButton').pack(side=tk.LEFT, padx=4)

        # Filters
        filter_card = ttk.LabelFrame(content, text='Filters', padding=16, style='Card.TFrame')
        filter_card.pack(fill=tk.X, pady=(0, 16))

        filter_inner = ttk.Frame(filter_card, style='Card.TFrame')
        filter_inner.pack(fill=tk.X)

        ttk.Label(filter_inner, text='Search:', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 8))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(filter_inner, textvariable=self.search_var, width=32, font=('Segoe UI', 10))
        search_entry.pack(side=tk.LEFT, padx=(0, 16), fill=tk.X, expand=True)
        search_entry.bind('<KeyRelease>', lambda e: self.filter_packets())

        # Additional quick filters: src/dst IP and ports
        ttk.Label(filter_inner, text='Src:', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 8))
        self.src_var = tk.StringVar()
        src_entry = ttk.Entry(filter_inner, textvariable=self.src_var, width=18, font=('Segoe UI', 10))
        src_entry.pack(side=tk.LEFT, padx=(0, 8))
        src_entry.bind('<KeyRelease>', lambda e: self.filter_packets())

        ttk.Label(filter_inner, text='Dst:', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 8))
        self.dst_var = tk.StringVar()
        dst_entry = ttk.Entry(filter_inner, textvariable=self.dst_var, width=18, font=('Segoe UI', 10))
        dst_entry.pack(side=tk.LEFT, padx=(0, 8))
        dst_entry.bind('<KeyRelease>', lambda e: self.filter_packets())

        ttk.Label(filter_inner, text='Src Port:', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 8))
        self.srcport_var = tk.StringVar()
        srcport_entry = ttk.Entry(filter_inner, textvariable=self.srcport_var, width=8, font=('Segoe UI', 10))
        srcport_entry.pack(side=tk.LEFT, padx=(0, 8))
        srcport_entry.bind('<KeyRelease>', lambda e: self.filter_packets())

        ttk.Label(filter_inner, text='Dst Port:', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 8))
        self.dstport_var = tk.StringVar()
        dstport_entry = ttk.Entry(filter_inner, textvariable=self.dstport_var, width=8, font=('Segoe UI', 10))
        dstport_entry.pack(side=tk.LEFT, padx=(0, 8))
        dstport_entry.bind('<KeyRelease>', lambda e: self.filter_packets())

        ttk.Label(filter_inner, text='Protocol:', font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 8))
        self.protocol_var = tk.StringVar(value='All')
        protocol_combo = ttk.Combobox(filter_inner, textvariable=self.protocol_var, values=PROTOCOL_OPTIONS, state='readonly', width=12, font=('Segoe UI', 10))
        protocol_combo.pack(side=tk.LEFT)
        protocol_combo.bind('<<ComboboxSelected>>', lambda e: self.filter_packets())

        # Use a vertical paned window: top = packet table, bottom = details panes
        paned_v = tk.PanedWindow(content, orient=tk.VERTICAL)
        paned_v.pack(fill=tk.BOTH, expand=True)
        self.v_paned = paned_v

        # Packet table (top pane)
        table_card = ttk.LabelFrame(paned_v, text='Captured Packets', padding=16, style='Card.TFrame')
        paned_v.add(table_card)

        table_frame = ttk.Frame(table_card, style='Card.TFrame')
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ('Time', 'Size', 'Source IP', 'Dest IP', 'Protocol', 'DNS', 'Port Info')
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings', selectmode='browse', height=12)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree.column('#0', width=0, stretch=tk.NO)
        for col in cols:
            # More generous default widths and allow stretching
            if col == 'Time':
                width = 220
            elif col == 'Size':
                width = 90
            elif col == 'Source IP' or col == 'Dest IP':
                width = 180
            elif col == 'Protocol':
                width = 100
            elif col == 'DNS':
                width = 180
            elif col == 'Port Info':
                width = 180
            else:
                width = 140
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor='w', width=width, stretch=True)

        # Prefer a taller initial table to fill the capture area
        try:
            self.tree.config(height=20)
        except Exception:
            pass
        # Bind selection and configure row tags and scrollbar + details area
        try:
            self.tree.bind('<<TreeviewSelect>>', self.on_select)
            self.tree.tag_configure('even', background=DARK_BORDER if self.dark_theme else LIGHT_SIDEBAR)
            self.tree.tag_configure('odd', background=DARK_CARD if self.dark_theme else LIGHT_CARD)

            scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.tree.configure(yscrollcommand=scrollbar.set)

            # Details area split: left = layer/fields; right = hexdump (bottom pane)
            details_card = ttk.LabelFrame(paned_v, text='Packet Details', padding=8, style='Card.TFrame')
            paned_v.add(details_card)

            paned = tk.PanedWindow(details_card, orient=tk.HORIZONTAL)
            self.details_paned = paned
            paned.pack(fill=tk.BOTH, expand=True)

            left_frame = tk.Frame(paned, bg=DARK_CARD if self.dark_theme else LIGHT_CARD)
            paned.add(left_frame, stretch='always')

            # Layer/fields text (left)
            self.layer_text = tk.Text(left_frame, height=12, wrap=tk.WORD, bg=DARK_BG if self.dark_theme else LIGHT_BG, fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT, bd=0, font=('Courier', 10), insertbackground=PRIMARY)
            self.layer_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
            layer_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.layer_text.yview)
            layer_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            self.layer_text.configure(yscrollcommand=layer_scroll.set)

            # Attempt to position sash at half the available height so capture occupies upper half
            try:
                # if user previously saved sash pos, restore it
                saved = self.ui_config.get('sash_pos') if hasattr(self, 'ui_config') else None
                if saved:
                            self.root.after(300, lambda pv=paned_v, s=saved: pv.sash_place(0, 0, int(s)))
                else:
                    self.root.after(300, lambda pv=paned_v: pv.sash_place(0, 0, int(self.content_frame.winfo_height() / 2) or 300))
                # bind release on paned to save sash position
                try:
                    def _save_sash(e=None, pv=paned_v, cfg=self.ui_config, path=self.config_file):
                        try:
                            coord = pv.sash_coord(0)
                            if coord:
                                y = int(coord[1])
                                cfg['sash_pos'] = y
                                with open(path, 'w', encoding='utf-8') as cf:
                                    json.dump(cfg, cf)
                        except Exception:
                            pass
                    paned_v.bind('<ButtonRelease-1>', _save_sash)
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass

        # Populate table with any packets captured while the capture view was hidden
        try:
            if hasattr(self, 'packet_items') and self.packet_items:
                # Preserve insertion order by packet_sequence numeric suffix in iid
                for iid in sorted(self.packet_items.keys(), key=lambda x: int(x.split('_')[-1])):
                    pkt = self.packet_items[iid]
                    try:
                        if hasattr(self, 'tree') and self.tree.winfo_exists():
                            self.tree.insert('', tk.END, iid=iid, values=(pkt['time'], pkt.get('length', 0), pkt['src'], pkt['dst'], pkt['proto'], pkt.get('dns', ''), pkt.get('info', '')), tags=('even' if len(self.tree.get_children()) % 2 == 0 else 'odd',))
                    except Exception:
                        pass
        except Exception:
            pass

    def periodic_refresh_interfaces(self):
        try:
            self.refresh_interfaces()
        except Exception:
            pass
        try:
            self.root.after(10000, self.periodic_refresh_interfaces)
        except Exception:
            pass

    def on_iface_change(self):
        # Called when user selects a different interface from combobox
        try:
            new = self.iface_var.get()
            if getattr(self, 'sniffer_running', False) or globals().get('sniffer_running', False):
                # ask user to stop capture before switching
                if messagebox.askyesno('Switch Interface', 'Capture is running. Stop capture and switch interface?'):
                    try:
                        self.stop_capture()
                    except Exception:
                        pass
                else:
                    # revert selection to previous
                    try:
                        if hasattr(self, 'iface_prev') and self.iface_prev:
                            self.iface_var.set(self.iface_prev)
                    except Exception:
                        pass
                    return
            # remember previous selection
            try:
                self.iface_prev = new
            except Exception:
                pass
            # refresh visible packet list for the selected interface
            try:
                self.filter_packets()
            except Exception:
                pass
        except Exception:
            pass

    def add_packet_record(self, pkt):
        item_id = f'pkt_{self.packet_sequence}'
        self.packet_sequence += 1
        self.packet_items[item_id] = pkt
        self.protocol_stats[pkt['proto']] += 1
        if pkt.get('src'):
            self.ip_stats[pkt['src']] += 1
        try:
            if hasattr(self, 'tree') and self.tree.winfo_exists():
                tag = 'even' if len(self.tree.get_children()) % 2 == 0 else 'odd'
                self.tree.insert('', tk.END, iid=item_id, values=(pkt['time'], pkt.get('length', 0), pkt['src'], pkt['dst'], pkt['proto'], pkt.get('dns', ''), pkt.get('info', '')), tags=(tag,))
        except Exception:
            pass
        try:
            self.total_bytes += int(pkt.get('length', 0) or 0)
            self.packet_count += 1
            self.update_status()
        except Exception:
            pass

    def build_analyst_tab(self):
        header = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        header.pack(fill=tk.X)

        ttk.Label(header, text='Advanced Analysis', style='Title.TLabel').pack(anchor='w')
        ttk.Label(header, text='Deep packet inspection and statistical analysis', style='Subtitle.TLabel').pack(anchor='w', pady=(4, 0))

        content = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        content.pack(fill=tk.BOTH, expand=True)

        # Top row
        top_row = ttk.Frame(content, style='Content.TFrame')
        top_row.pack(fill=tk.BOTH, expand=True, pady=(0, 16))

        proto_card = ttk.LabelFrame(top_row, text='Protocol Breakdown', padding=16, style='Card.TFrame')
        proto_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        self.proto_analysis_tree = ttk.Treeview(proto_card, columns=('Protocol', 'Count', 'Percentage'), show='headings', height=10)
        self.proto_analysis_tree.pack(fill=tk.BOTH, expand=True)

        self.proto_analysis_tree.heading('Protocol', text='Protocol')
        self.proto_analysis_tree.heading('Count', text='Count')
        self.proto_analysis_tree.heading('Percentage', text='%')
        self.proto_analysis_tree.column('Protocol', width=120)
        self.proto_analysis_tree.column('Count', width=80)
        self.proto_analysis_tree.column('Percentage', width=80)

        ip_card = ttk.LabelFrame(top_row, text='Top Source IPs', padding=16, style='Card.TFrame')
        ip_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

        self.ip_analysis_tree = ttk.Treeview(ip_card, columns=('IP', 'Count', 'Percentage'), show='headings', height=10)
        self.ip_analysis_tree.pack(fill=tk.BOTH, expand=True)

        self.ip_analysis_tree.heading('IP', text='Source IP')
        self.ip_analysis_tree.heading('Count', text='Packets')
        self.ip_analysis_tree.heading('Percentage', text='%')
        self.ip_analysis_tree.column('IP', width=150)
        self.ip_analysis_tree.column('Count', width=80)
        self.ip_analysis_tree.column('Percentage', width=80)

        # Bottom
        chart_row = ttk.Frame(content, style='Content.TFrame')
        chart_row.pack(fill=tk.BOTH, expand=True)

        pie_card = ttk.LabelFrame(chart_row, text='Protocol Distribution', padding=16, style='Card.TFrame')
        pie_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        self.pie_figure = Figure(figsize=(5, 4), dpi=100, facecolor=DARK_CARD if self.dark_theme else LIGHT_CARD)
        self.pie_ax = self.pie_figure.add_subplot(111)
        self.pie_canvas = FigureCanvasTkAgg(self.pie_figure, pie_card)
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        stats_card = ttk.LabelFrame(chart_row, text='Statistics Summary', padding=16, style='Card.TFrame')
        stats_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0))

        self.stats_text = tk.Text(stats_card, height=18, wrap=tk.WORD, bg=DARK_BG if self.dark_theme else LIGHT_BG, fg=DARK_TEXT if self.dark_theme else LIGHT_TEXT, bd=0, font=('Courier', 9))
        self.stats_text.pack(fill=tk.BOTH, expand=True)

    def build_alerts_tab(self):
        header = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        header.pack(fill=tk.X)

        ttk.Label(header, text='Security Alerts', style='Title.TLabel').pack(anchor='w')
        ttk.Label(header, text='Detected anomalies and potential threats', style='Subtitle.TLabel').pack(anchor='w', pady=(4, 0))

        content = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        content.pack(fill=tk.BOTH, expand=True)

        table_frame = ttk.Frame(content, style='Content.TFrame')
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ('Time', 'Severity', 'Type', 'Source', 'Description')
        self.alerts_tree = ttk.Treeview(table_frame, columns=cols, show='headings', selectmode='browse')
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for col in cols:
            width = 120 if col != 'Description' else 350
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, anchor='w', width=width)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)

        self.alerts_tree.insert('', tk.END, values=('--:--:--', 'Info', 'System', 'N/A', 'Monitoring enabled'))

    def build_settings_tab(self):
        header = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        header.pack(fill=tk.X)

        ttk.Label(header, text='Settings', style='Title.TLabel').pack(anchor='w')
        ttk.Label(header, text='Configure application preferences', style='Subtitle.TLabel').pack(anchor='w', pady=(4, 0))

        content = ttk.Frame(self.content_frame, style='Content.TFrame', padding=20)
        content.pack(fill=tk.BOTH, expand=False)

        gen_card = ttk.LabelFrame(content, text='General Settings', padding=16, style='Card.TFrame')
        gen_card.pack(fill=tk.X, pady=(0, 16))

        setting_frame = ttk.Frame(gen_card, style='Card.TFrame')
        setting_frame.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(setting_frame, text='Theme:', font=('Segoe UI', 10)).pack(side=tk.LEFT)
        ttk.Button(setting_frame, text='🌙 Dark / ☀️ Light', command=self.toggle_theme, style='Secondary.TButton').pack(side=tk.LEFT, padx=(12, 0))

        setting_frame2 = ttk.Frame(gen_card, style='Card.TFrame')
        setting_frame2.pack(fill=tk.X)

        ttk.Label(setting_frame2, text='Max Packets:', font=('Segoe UI', 10)).pack(side=tk.LEFT)
        max_packets_var = tk.StringVar(value=str(self.max_packets))
        ttk.Entry(setting_frame2, textvariable=max_packets_var, width=10, font=('Segoe UI', 10)).pack(side=tk.LEFT, padx=(12, 0))

    def build_status_bar(self):
        status = tk.Frame(self.root, bg=DARK_CARD if self.dark_theme else LIGHT_CARD, relief='flat', highlightthickness=1, highlightbackground=DARK_BORDER if self.dark_theme else LIGHT_BORDER)
        status.pack(fill=tk.X, side=tk.BOTTOM)

        status_inner = tk.Frame(status, bg=DARK_CARD if self.dark_theme else LIGHT_CARD)
        status_inner.pack(fill=tk.BOTH, padx=12, pady=8)

        self.status_var = tk.StringVar(value='Ready')
        status_label = tk.Label(status_inner, textvariable=self.status_var, font=('Segoe UI', 9),
                               bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                               fg=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
        status_label.pack(side=tk.LEFT)

        self.time_label = tk.Label(status_inner, text='', font=('Segoe UI', 9),
                                  bg=DARK_CARD if self.dark_theme else LIGHT_CARD,
                                  fg=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
        self.time_label.pack(side=tk.RIGHT)

    def update_loop(self):
        try:
            self.update_all_charts()
            self.time_label.config(text=datetime.now().strftime('%H:%M:%S'))
        except Exception:
            pass

        self.root.after(1000, self.update_loop)

    def rebuild_ui(self):
        try:
            for child in self.root.winfo_children():
                child.destroy()
            self.style = ttk.Style()
            self.configure_custom_style()
            self.root.configure(bg=DARK_BG if self.dark_theme else LIGHT_BG)

            main_container = ttk.Frame(self.root)
            main_container.pack(fill=tk.BOTH, expand=True)
            self.build_sidebar(main_container)
            self.build_main_content(main_container, self.current_view)
            self.build_status_bar()
            self.refresh_interfaces()
        except Exception:
            pass

    def update_all_charts(self):
        if self.current_view == 'dashboard':
            self.update_dashboard()
        elif self.current_view == 'analyst':
            self.update_analyst()

    def update_dashboard(self):
        try:
            self.stat_cards['total'].config(text=str(self.packet_count))
            self.stat_cards['tcp'].config(text=str(self.protocol_stats.get('TCP', 0)))
            self.stat_cards['udp'].config(text=str(self.protocol_stats.get('UDP', 0)))
            self.stat_cards['icmp'].config(text=str(self.protocol_stats.get('ICMP', 0)))

            self.proto_ax.clear()
            if self.protocol_stats:
                protocols = list(self.protocol_stats.keys())[:7]
                counts = [self.protocol_stats[p] for p in protocols]
                self.proto_ax.pie(counts, labels=protocols, autopct='%1.0f%%', colors=COLORS)
                self.proto_ax.set_facecolor(DARK_CARD if self.dark_theme else LIGHT_CARD)
            self.proto_canvas.draw()

            self.traffic_ax.clear()
            if len(self.packet_items) > 0:
                cumulative = list(range(1, len(self.packet_items) + 1))
                self.traffic_ax.plot(cumulative, color=PRIMARY_LIGHT, linewidth=2.5)
                self.traffic_ax.fill_between(range(len(cumulative)), cumulative, alpha=0.2, color=PRIMARY_LIGHT)
                self.traffic_ax.set_xlabel('Packets', color=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
                self.traffic_ax.set_ylabel('Cumulative Count', color=DARK_TEXT_SECONDARY if self.dark_theme else LIGHT_TEXT_SECONDARY)
                self.traffic_ax.set_facecolor(DARK_CARD if self.dark_theme else LIGHT_CARD)
                self.traffic_ax.grid(True, alpha=0.1)
            self.traffic_canvas.draw()
        except Exception:
            pass

    def update_analyst(self):
        try:
            for item in self.proto_analysis_tree.get_children():
                self.proto_analysis_tree.delete(item)

            total = sum(self.protocol_stats.values())
            for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                pct = (count / total * 100) if total > 0 else 0
                self.proto_analysis_tree.insert('', tk.END, values=(proto, count, f'{pct:.1f}%'))

            for item in self.ip_analysis_tree.get_children():
                self.ip_analysis_tree.delete(item)

            for ip, count in sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:20]:
                pct = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                self.ip_analysis_tree.insert('', tk.END, values=(ip, count, f'{pct:.1f}%'))

            self.pie_ax.clear()
            if self.protocol_stats:
                protocols = list(self.protocol_stats.keys())
                counts = [self.protocol_stats[p] for p in protocols]
                colors = COLORS * ((len(protocols) // len(COLORS)) + 1)
                self.pie_ax.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors[:len(protocols)])
                self.pie_ax.set_facecolor(DARK_CARD if self.dark_theme else LIGHT_CARD)
            self.pie_canvas.draw()

            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete('1.0', tk.END)

            stats_content = f"""╔════════════════════════════════════════╗
║   PACKET CAPTURE STATISTICS            ║
╚════════════════════════════════════════╝

Total Packets:          {self.packet_count:,}
Unique Source IPs:      {len(self.ip_stats)}
Max Stored:             {self.max_packets:,}

Protocol Breakdown:
{'-' * 40}"""

            for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                pct = (count / self.packet_count * 100) if self.packet_count > 0 else 0
                stats_content += f"\n  {proto:<15} {count:>8}  ({pct:>5.1f}%)"

            stats_content += f"""

Top 10 Source IPs:
{'-' * 40}"""

            for ip, count in sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                stats_content += f"\n  {ip:<20} {count:>8}"

            self.stats_text.insert('1.0', stats_content)
            self.stats_text.config(state=tk.DISABLED)
        except Exception:
            pass

    def refresh_interfaces(self):
        self.interface_map = {}
        options = []
        for display_name, actual_name in list_interfaces():
            options.append(display_name)
            self.interface_map[display_name] = actual_name

        if not options:
            options = ['default']
            self.interface_map['default'] = None

        # Only update the combo box if it exists (it's created in build_capture_tab)
        if hasattr(self, 'iface_combo'):
            self.iface_combo['values'] = options
            if not self.iface_var.get() or self.iface_var.get() not in options:
                self.iface_var.set(options[0])
            try:
                self.iface_prev = self.iface_var.get()
            except Exception:
                self.iface_prev = None

    def start_capture(self):
        global sniffer, sniffer_running
        try:
            if AsyncSniffer is None:
                messagebox.showerror('Missing dependency', 'Scapy is required. Install it with: pip install scapy')
                return
            if sniffer_running:
                self.status_var.set('⚠ Capture already running')
                return
            # defensive: ensure iface var exists
            selected = self.iface_var.get() if hasattr(self, 'iface_var') else ''
            iface = self.interface_map.get(selected, selected) if hasattr(self, 'interface_map') else selected
            if not iface:
                iface = None
            # log attempt
            try:
                with open(LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"Start capture requested: selected='{selected}', iface='{iface}'\n")
            except Exception:
                pass
            if iface is None and not selected:
                self.status_var.set('⚠ No interface selected')
                messagebox.showwarning('Capture', 'No interface selected. Please choose an interface.')
                return

            # wrap prn to include iface info so packets can be separated per-interface
            sniffer = AsyncSniffer(iface=iface, prn=lambda *args, iface=iface: packet_handler(args[0], iface), store=False)
            sniffer.start()
            sniffer_running = True
            self.status_var.set(f'✓ Capturing on: {selected or "default"}')
            try:
                self.sidebar_status.config(text='● Capturing', foreground=SECONDARY)
            except Exception:
                pass
        except Exception as exc:
            # write traceback to log and alert user
            import traceback
            tb = traceback.format_exc()
            try:
                with open(LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"Start capture failed: {exc}\n{tb}\n")
            except Exception:
                pass
            messagebox.showerror('Capture error', f'Unable to start capture:\n{exc}')
            self.status_var.set('✗ Capture failed')

    def stop_capture(self):
        global sniffer, sniffer_running
        if not sniffer_running or sniffer is None:
            self.status_var.set('⚠ Capture is not running')
            return
        try:
            sniffer.stop()
        except Exception:
            pass
        sniffer_running = False
        self.status_var.set('⏹ Capture stopped')
        self.sidebar_status.config(text='● Ready', foreground=SECONDARY)

    def clear_view(self):
        try:
            if hasattr(self, 'tree') and self.tree.winfo_exists():
                for item in self.tree.get_children():
                    try:
                        self.tree.delete(item)
                    except Exception:
                        pass
        except Exception:
            pass
        self.packet_items.clear()
        # also reset previous interface memory
        try:
            self.iface_prev = self.iface_var.get() if hasattr(self, 'iface_var') else None
        except Exception:
            pass
        self.packet_sequence = 0
        self.packet_count = 0
        self.protocol_stats.clear()
        self.ip_stats.clear()
        try:
            if hasattr(self, 'layer_text'):
                try:
                    self.layer_text.config(state=tk.NORMAL)
                    self.layer_text.delete('1.0', tk.END)
                    self.layer_text.config(state=tk.DISABLED)
                except Exception:
                    pass
        except Exception:
            pass
        self.status_var.set('View cleared')
        self.sidebar_count.config(text='TCP: 0 | UDP: 0')

    def filter_packets(self, *args):
        query = self.search_var.get().strip().lower()
        protocol_filter = self.protocol_var.get().upper() if hasattr(self, 'protocol_var') else 'ALL'
        src_filter = self.src_var.get().strip().lower() if hasattr(self, 'src_var') else ''
        dst_filter = self.dst_var.get().strip().lower() if hasattr(self, 'dst_var') else ''
        srcport_filter = self.srcport_var.get().strip() if hasattr(self, 'srcport_var') else ''
        dstport_filter = self.dstport_var.get().strip() if hasattr(self, 'dstport_var') else ''
        # interface filter: show only selected interface's packets (unless 'default')
        selected_display = self.iface_var.get() if hasattr(self, 'iface_var') else None
        selected_iface = None
        try:
            if selected_display and hasattr(self, 'interface_map'):
                selected_iface = self.interface_map.get(selected_display, selected_display)
        except Exception:
            selected_iface = selected_display
        try:
            if hasattr(self, 'tree') and self.tree.winfo_exists():
                self.tree.delete(*self.tree.get_children())
        except Exception:
            pass
        for item_id, pkt in self.packet_items.items():
            if protocol_filter != 'ALL' and pkt['proto'].upper() != protocol_filter:
                continue
            fields = ' '.join(
                [pkt.get('src', ''), pkt.get('dst', ''), pkt.get('src_mac', ''), pkt.get('dst_mac', ''), pkt.get('src_port', ''), pkt.get('dst_port', ''), pkt.get('proto', ''), pkt.get('info', ''), pkt.get('raw', '')]
            ).lower()
            if query and query not in fields:
                continue
            if src_filter and src_filter not in (pkt.get('src') or '').lower():
                continue
            if dst_filter and dst_filter not in (pkt.get('dst') or '').lower():
                continue
            if srcport_filter and srcport_filter not in str(pkt.get('src_port', '')):
                continue
            if dstport_filter and dstport_filter not in str(pkt.get('dst_port', '')):
                continue
            # interface separation
            if selected_iface and pkt.get('iface') and pkt.get('iface') != selected_iface:
                continue
            tag = 'even' if (hasattr(self, 'tree') and self.tree.winfo_exists() and len(self.tree.get_children()) % 2 == 0) else 'odd'
            try:
                if hasattr(self, 'tree') and self.tree.winfo_exists():
                    self.tree.insert('', tk.END, iid=item_id, values=(pkt['time'], pkt.get('length', 0), pkt['src'], pkt['dst'], pkt['proto'], pkt.get('dns', ''), pkt['info']), tags=(tag,))
            except Exception:
                pass

    def on_select(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        pkt = self.packet_items.get(selection[0])
        if not pkt:
            return
        # Build detailed, Wireshark-like view if original packet is available
        try:
            # Log selection for debugging
            try:
                with open(LOG_FILE, 'a', encoding='utf-8') as lf:
                    lf.write(f"Selection: {selection[0]}\n")
            except Exception:
                pass

            # Prepare left pane content (basics + layers)
            header = f"""╔═══════════════════════════════════════════╗
║           PACKET DETAILS                  ║
╚═══════════════════════════════════════════╝\n\n"""
            basics = f"""Timestamp:        {pkt.get('time', 'N/A')}
Protocol:         {pkt.get('proto', 'N/A')}
Source IP:        {pkt.get('src', 'N/A')}
Destination IP:   {pkt.get('dst', 'N/A')}
Source MAC:       {pkt.get('src_mac', 'N/A')}
Destination MAC:  {pkt.get('dst_mac', 'N/A')}
Source Port:      {pkt.get('src_port', 'N/A')}
Destination Port: {pkt.get('dst_port', 'N/A')}
Info:             {pkt.get('info', 'N/A')}
Packet Length:    {pkt.get('length', 'N/A')}
Payload Length:   {pkt.get('payload_len', 'N/A')}
DNS:              {pkt.get('dns', '') or 'N/A'}\n\n"""

            left_lines = [header, basics]

            raw_packet = pkt.get('raw_packet')
            if raw_packet is not None:
                try:
                    p = raw_packet
                    layer_index = 0
                    left_lines.append('Layer breakdown:\n')
                    left_lines.append('-' * 60 + '\n')
                    while p and p.__class__.__name__ != 'NoPayload':
                        layer_name = p.__class__.__name__
                        left_lines.append(f"[{layer_index}] {layer_name}\n")
                        try:
                            for fname, fval in getattr(p, 'fields', {}).items():
                                try:
                                    left_lines.append(f"  {fname}: {fval}\n")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        left_lines.append('\n')
                        layer_index += 1
                        try:
                            p = p.payload
                        except Exception:
                            break
                except Exception:
                    pass

            # Write to left pane only
            try:
                if hasattr(self, 'layer_text'):
                    self.layer_text.config(state=tk.NORMAL)
                    self.layer_text.delete('1.0', tk.END)
                    self.layer_text.insert(tk.END, ''.join(left_lines))
                    self.layer_text.config(state=tk.DISABLED)
            except Exception:
                pass
        except Exception:
            try:
                if hasattr(self, 'layer_text'):
                    self.layer_text.config(state=tk.NORMAL)
                    self.layer_text.delete('1.0', tk.END)
                    self.layer_text.insert(tk.END, 'Unable to render packet details.')
                    self.layer_text.config(state=tk.DISABLED)
            except Exception:
                pass

        tcp_count = self.protocol_stats.get('TCP', 0)
        udp_count = self.protocol_stats.get('UDP', 0)
        self.sidebar_count.config(text=f'TCP: {tcp_count} | UDP: {udp_count}')

    def update_status(self):
        tcp_count = self.protocol_stats.get('TCP', 0)
        udp_count = self.protocol_stats.get('UDP', 0)
        self.sidebar_count.config(text=f'TCP: {tcp_count} | UDP: {udp_count}')
        try:
            if hasattr(self, 'sidebar_bytes'):
                self.sidebar_bytes.config(text=f'Bytes: {self.total_bytes:,}')
        except Exception:
            pass

    def save_selected(self):
        sel = None
        try:
            sel = self.tree.selection()
        except Exception:
            pass
        if not sel:
            messagebox.showinfo('Save', 'No packet selected')
            return
        pkt = self.packet_items.get(sel[0])
        if not pkt:
            messagebox.showinfo('Save', 'Selected packet not available')
            return
        self._save_packet_record(pkt, 'Selected packet saved')

    def save_capture(self):
        if not self.packet_items:
            messagebox.showinfo('Save', 'No packets available to save')
            return
        # Ask save file
        try:
            path = filedialog.asksaveasfilename(defaultextension='.pcap', filetypes=[('PCAP','*.pcap'),('PCAPNG','*.pcapng'),('JSON','*.json'),('Text','*.txt')])
            if not path:
                return
        except Exception:
            messagebox.showerror('Save', 'Unable to choose file')
            return
        try:
            ext = os.path.splitext(path)[1].lower()
            if ext in ('.pcap', '.pcapng'):
                packets = [pkt.get('raw_packet') for pkt in self.packet_items.values() if pkt.get('raw_packet') is not None]
                if not packets:
                    messagebox.showerror('Save', 'No raw packets available to write PCAP')
                    return
                from scapy.utils import wrpcap
                wrpcap(path, packets)
            else:
                out = []
                for pkt in self.packet_items.values():
                    out.append({k: (str(v) if k == 'raw_packet' else v) for k, v in pkt.items()})
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(out, f, indent=2, default=str)
            messagebox.showinfo('Save', f'Captured traffic saved to {path}')
        except Exception as exc:
            messagebox.showerror('Save', f'Failed to save capture:\n{exc}')

    def _save_packet_record(self, pkt, success_message):
        try:
            path = filedialog.asksaveasfilename(defaultextension='.pcap', filetypes=[('PCAP','*.pcap'),('JSON','*.json'),('Text','*.txt')])
            if not path:
                return
        except Exception:
            messagebox.showerror('Save', 'Unable to choose file')
            return
        try:
            ext = os.path.splitext(path)[1].lower()
            if ext == '.pcap':
                if pkt.get('raw_packet') is None:
                    messagebox.showerror('Save', 'No raw packet data available to write PCAP')
                    return
                from scapy.utils import wrpcap
                wrpcap(path, [pkt.get('raw_packet')])
            else:
                out = {k: (str(v) if k == 'raw_packet' else v) for k, v in pkt.items()}
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(out, f, indent=2, default=str)
            messagebox.showinfo('Save', f'{success_message}: {path}')
        except Exception as exc:
            messagebox.showerror('Save', f'Failed to save packet:\n{exc}')

    def load_capture(self):
        try:
            path = filedialog.askopenfilename(filetypes=[('PCAP','*.pcap'),('PCAPNG','*.pcapng'),('JSON','*.json'),('Text','*.txt')])
            if not path:
                return
        except Exception:
            messagebox.showerror('Load', 'Unable to choose file')
            return
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext in ('.pcap', '.pcapng'):
                from scapy.utils import rdpcap
                packets = rdpcap(path)
                if not packets:
                    messagebox.showinfo('Load', 'No packets found in file')
                    return
                self.clear_view()
                for packet in packets:
                    packet_handler(packet)
                self.status_var.set(f'Loaded {len(packets)} packets from {os.path.basename(path)}')
            else:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    data = [data]
                self.clear_view()
                loaded = 0
                for item in data:
                    if isinstance(item, dict):
                        pkt = {
                            'time': item.get('time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                            'src': item.get('src', ''),
                            'dst': item.get('dst', ''),
                            'src_mac': item.get('src_mac', ''),
                            'dst_mac': item.get('dst_mac', ''),
                            'src_port': item.get('src_port', ''),
                            'dst_port': item.get('dst_port', ''),
                            'proto': item.get('proto', 'OTHER'),
                            'info': item.get('info', ''),
                            'raw': item.get('raw', ''),
                            'raw_hex': item.get('raw_hex', ''),
                            'length': item.get('length', 0),
                            'payload_len': item.get('payload_len', 0),
                            'dns': item.get('dns', ''),
                            'raw_packet': None,
                        }
                        self.add_packet_record(pkt)
                        loaded += 1
                self.status_var.set(f'Loaded {loaded} packets from {os.path.basename(path)}')
        except Exception as exc:
            messagebox.showerror('Load', f'Failed to load capture:\n{exc}')

    def toggle_theme(self):
        self.dark_theme = not self.dark_theme
        self.rebuild_ui()
        try:
            self.status_var.set(f'✓ Switched to {"Dark" if self.dark_theme else "Light"} theme')
        except Exception:
            pass

    def on_close(self):
        self.stop_capture()
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass


if __name__ == '__main__':
    root = tk.Tk()
    app = NetworkSnifferGUI(root)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.on_close()
