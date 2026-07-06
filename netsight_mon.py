# =============================================================================
# TOOL NAME= "NetSight Monitor"
# Realtime Network Monitoring and Traffic Analysis Tool
#
# Author : Rajarshi Sarkar
# Final Year B.Tech CSE Project
#
# This tool is developed to monitor and analyze live network traffic in an
# easy and organized way. It captures packets in realtime, identifies various
# network protocols, discovers connected devices and generates professional
# PDF reports for network analysis.
#
# Features:
# • Realtime Packet Capture
# • Protocol Detection and Analysis Packets Count
# • HTTP / Form Event Monitoring
# • Connected Device Discovery
# • DNS and Domain Resolution   --- JO KI NEHI KAR PAYA :( | NEED MORE RESEARCH ABOUT THIS..
# • Implement IDS               --- JO KI NEHI KAR PAYA :( | NEED MORE RESEARCH ABOUT THIS..
# • Professional PDF Report Generation
#
# The project is divided into multiple sections so that the code remains
# clean, understandable and easy to maintain in the future.
# =============================================================================

# -----------------------------
# Standard library imports
# OS, threading, socket, regex, date/time aur helper modules yahan import hote hain.
# -----------------------------
import sys
import os
import threading
import socket
import traceback
import ipaddress
import urllib.parse
import re
from collections import Counter, defaultdict
from datetime import datetime

# -----------------------------
# Third-party imports
# requests public IP ke liye, Scapy packet capture/parse ke liye,
# FPDF report export ke liye, aur PyQt6 desktop GUI ke liye use hota hai.
# -----------------------------
import requests
import scapy.all as scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, srp, conf, DNS, DNSQR, Raw
from scapy.interfaces import get_working_ifaces
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
from scapy.utils import hexdump

from fpdf import FPDF
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QTextEdit, QLabel,
    QTabWidget, QComboBox, QSplitter, QAbstractItemView, QLineEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# -----------------------------
# Global configuration
# Tool name, author name, export folder aur UI row limit yahan set hai.
# In values ko change karne se branding/output behavior update hoga.
# -----------------------------
AUTHOR_NAME = "Rajarshi Sarkar"
TOOL_NAME = "NetSight Monitor"
EXPORT_DIR = "exported_reports"
MAX_UI_ROWS = 5000

# Large port-to-application map for wider protocol visibility in live table and PDF.
# This is metadata identification only; encrypted payloads such as HTTPS/SSH remain encrypted.
# -----------------------------
# Port-to-application mapping
# Ye dictionary common well-known ports ko readable protocol/app name me convert karti hai.
# Example: 80 -> HTTP, 443 -> HTTPS/TLS, 22 -> SSH.
# -----------------------------

# Large port-to-application map for wider protocol visibility in live table and PDF.
# This is metadata identification only; encrypted payloads such as HTTPS/SSH remain encrypted.
PORT_PROTOCOLS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "KERBEROS", 110: "POP3", 111: "RPCBIND", 123: "NTP", 135: "MSRPC",
    137: "NETBIOS-NS", 138: "NETBIOS-DGM", 139: "NETBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP", 443: "HTTPS/TLS",
    445: "SMB", 465: "SMTPS", 500: "IKE/IPSEC", 514: "SYSLOG", 515: "LPD",
    587: "SMTP-SUBMISSION", 631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "ORACLE-DB", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2375: "DOCKER", 2376: "DOCKER-TLS", 3306: "MYSQL", 3389: "RDP",
    5432: "POSTGRESQL", 5672: "AMQP", 5900: "VNC", 5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS", 6379: "REDIS", 8000: "HTTP-ALT", 8080: "HTTP-ALT",
    8081: "HTTP-ALT", 8443: "HTTPS-ALT", 8888: "HTTP-ALT", 9200: "ELASTICSEARCH",
    9300: "ELASTICSEARCH", 11211: "MEMCACHED", 27017: "MONGODB"
}
# -----------------------------
# HTTP parsing regex and flow buffer limit
# Raw TCP payload me HTTP request/response detect karne ke liye regex patterns.
# Flow buffer fragmented HTTP data ko short-term memory me join karta hai.
# -----------------------------
HTTP_METHOD_RE = re.compile(rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/", re.I)
HTTP_RESPONSE_RE = re.compile(rb"^HTTP/\d\.\d\s+(\d{3})\s*(.*)", re.I)
MAX_HTTP_FLOW_BUFFER = 128 * 1024

# Report output folder create karta hai agar folder already present na ho.
os.makedirs(EXPORT_DIR, exist_ok=True)

# -----------------------------
# Global exception hook
# GUI me unexpected crash aaye to console par full traceback print hota hai.
# -----------------------------
def exception_hook(exctype, value, tb):
    print("\n[CRITICAL ERROR] UI Exception:")
    traceback.print_exception(exctype, value, tb)


sys.excepthook = exception_hook

# -----------------------------
# Text cleanup helper
# FPDF latin-1 friendly text expect karta hai, isliye unsafe characters ignore kiye jate hain.
# -----------------------------
def safe_text(value, limit=None):
    text = str(value) if value is not None else ""
    text = text.encode("latin-1", "ignore").decode("latin-1")
    return text[:limit] if limit else text

# -----------------------------
# Sensitive field redaction
# Kuch highly sensitive fields jaise OTP/PIN/CVV/cookie ko report/log me redact karta hai.
# -----------------------------
SENSITIVE_FIELD_RE = re.compile(r"(otp|pin|cvv|card|auth|session|cookie)", re.I)
def redact_field_value(name, value):
    """Keep form auditing useful but avoid exposing real secrets in logs/reports."""
    if SENSITIVE_FIELD_RE.search(str(name)):
        return "<REDACTED-SENSITIVE-FIELD>"
    return str(value)[:300]

# -----------------------------
# HTTP body extractor
# Header aur body ke beech CRLF separator milne par body part return karta hai.
# -----------------------------
def get_http_body(raw_bytes):
    """Return HTTP body if full HTTP message is present, otherwise return raw bytes."""
    if b"\r\n\r\n" in raw_bytes:
        return raw_bytes.split(b"\r\n\r\n", 1)[1]
    return raw_bytes

# -----------------------------
# application/x-www-form-urlencoded parser
# Normal HTML form fields ko key=value pairs me parse karta hai.
# -----------------------------
def parse_urlencoded_form(raw_bytes):
    try:
        body_bytes = get_http_body(raw_bytes)
        body = body_bytes.decode("utf-8", "replace")
        pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
        return [(k, redact_field_value(k, v)) for k, v in pairs]
    except Exception:
        return []

# -----------------------------
# JSON body parser
# JSON request body ke fields ko flatten karke readable list banata hai.
# -----------------------------
def parse_json_fields(raw_bytes):
    try:
        import json
        body = get_http_body(raw_bytes).decode("utf-8", "replace").strip()
        obj = json.loads(body)
        fields = []
        def walk(prefix, value):
            if isinstance(value, dict):
                for k, v in value.items():
                    walk(f"{prefix}.{k}" if prefix else str(k), v)
            elif isinstance(value, list):
                fields.append((prefix or "array", f"<list items={len(value)}>"))
            else:
                fields.append((prefix, redact_field_value(prefix, value)))
        walk("", obj)
        return fields[:100]
    except Exception:
        return []

# -----------------------------
# URL query parser
# GET request URL ke ?name=value fields ko extract karta hai.
# -----------------------------
def parse_query_fields(path):
    try:
        parsed = urllib.parse.urlparse(path)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        return [(k, redact_field_value(k, v)) for k, v in pairs]
    except Exception:
        return []

# -----------------------------
# Raw HTTP header parser
# Raw bytes se HTTP headers dictionary format me nikalta hai.
# -----------------------------
def parse_http_headers_from_raw(raw_bytes):
    headers = {}
    try:
        head = raw_bytes.split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("utf-8", "ignore").strip()] = v.decode("utf-8", "ignore").strip()
    except Exception:
        pass
    return headers

# -----------------------------
# Multipart form-data parser
# Text input fields parse karta hai; uploaded file content save/export nahi karta.
# -----------------------------
def parse_multipart_fields(raw_bytes, content_type):
    """Parse multipart/form-data text fields only.
    Uploaded file contents are intentionally not saved or exported.
    """
    fields, skipped_files = [], []
    try:
        body = raw_bytes.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw_bytes else raw_bytes
        boundary_match = re.search(r"boundary=([^;]+)", content_type, re.I)
        if not boundary_match:
            return fields, skipped_files
        boundary = boundary_match.group(1).strip().strip('"')
        delimiter = ("--" + boundary).encode("utf-8", "ignore")
        for part in body.split(delimiter):
            if not part or part in [b"--", b"--\r\n"] or b"\r\n\r\n" not in part:
                continue
            header_blob, payload = part.split(b"\r\n\r\n", 1)
            header_text = header_blob.decode("utf-8", "ignore")
            name_match = re.search(r'name="([^"]*)"', header_text, re.I)
            filename_match = re.search(r'filename="([^"]*)"', header_text, re.I)
            field_name = name_match.group(1) if name_match else "field"
            payload = payload.rstrip(b"\r\n-")
            if filename_match:
                skipped_files.append(filename_match.group(1) or "uploaded_file")
                continue
            try:
                value = payload.decode("utf-8", "replace")
            except Exception:
                value = "<binary-field>"
            fields.append((field_name, redact_field_value(field_name, value)))
    except Exception as exc:
        fields.append(("multipart_parse_error", str(exc)))
    return fields, skipped_files

# -----------------------------
# Scapy HTTPRequest header extractor
# Scapy parsed HTTP layer se headers ko normal dictionary me convert karta hai.
# -----------------------------
def http_headers_from_request(packet):
    headers = {}
    try:
        req = packet[HTTPRequest]
        for field in getattr(req, "fields_desc", []):
            name = field.name
            val = getattr(req, name, None)
            if val:
                key = name.replace("_", "-")
                headers[key] = val.decode("utf-8", "ignore") if isinstance(val, bytes) else str(val)
    except Exception:
        pass
    return headers





# =============================================================================
# PacketSniffer Thread
# Background thread me live packet capture chalata hai, packets analyze karta hai,
# HTTP/form events detect karta hai, DNS/TLS metadata resolve karta hai, aur GUI ko signals bhejta hai.
# =============================================================================
class PacketSniffer(QThread):
    packet_signal = pyqtSignal(dict)
    alert_signal = pyqtSignal(str)

    # Sniffer object initialize hota hai selected network interface ke sath.
    # dns_cache repeated reverse lookup ko avoid karta hai, http_flow_buffers fragmented HTTP stream ko join karta hai.
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = False
        self.dns_cache = {}
        self.http_flow_buffers = defaultdict(bytes)
    # QThread run method: Scapy sniff() yahan se start hota hai.
    # store=False memory save karta hai, promisc=True wider traffic visibility deta hai.
    def run(self):
        self.running = True
        try:
            sniff(iface=self.iface, prn=self.analyze_packet, store=False, promisc=True,
                  stop_filter=lambda _: not self.running)
        except Exception as e:
            self.alert_signal.emit(f"[!] Capture error: {str(e)}")
    # Capture stop karne ke liye running flag false hota hai.
    def stop(self):
        self.running = False

    # Background reverse DNS resolver: IP ko hostname me convert karne ki try karta hai.
    def active_dns_resolve(self, ip):
        try:
            host = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = host
        except Exception:
            self.dns_cache[ip] = "Unresolved"

    # Destination display builder: IP ke sath hostname/domain available ho to show karta hai.
    def resolve_display(self, ip):
        if ip not in self.dns_cache:
            self.dns_cache[ip] = "Resolving..."
            threading.Thread(target=self.active_dns_resolve, args=(ip,), daemon=True).start()
        host = self.dns_cache.get(ip, "")
        if host and host not in ["Resolving...", "Unresolved", ip]:
            return f"{ip} [{host}]", host
        return ip, ""
    # Packet layer + port number ke basis par application protocol guess karta hai.
    def detect_application_protocol(self, packet, base_proto):
        """Detect many common protocols by Scapy layer and well-known ports."""
        sport = dport = None
        if packet.haslayer(TCP):
            sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)

        ports = {p for p in [sport, dport] if p is not None}
        if packet.haslayer(DNS) or 53 in ports:
            return "DNS"
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            return "HTTP"
        if packet.haslayer(Raw):
            raw_start = bytes(packet[Raw].load[:16])
            if HTTP_METHOD_RE.search(raw_start) or HTTP_RESPONSE_RE.search(raw_start):
                return "HTTP"
        for p in ports:
            if p in PORT_PROTOCOLS:
                return PORT_PROTOCOLS[p]
        return base_proto

    # TCP/UDP flow identify karne ke liye 5-tuple key banata hai.
    def build_flow_key(self, packet):
        if packet.haslayer(TCP):
            return (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, "TCP")
        if packet.haslayer(UDP):
            return (packet[IP].src, packet[UDP].sport, packet[IP].dst, packet[UDP].dport, "UDP")
        return (packet[IP].src, packet[IP].dst, packet[IP].proto)

    # Buffered raw TCP bytes se HTTP request/response parse karta hai
    def parse_raw_http_message(self, raw):
        """Parse HTTP request/response from raw TCP bytes. Works for already-open sites too
        when new HTTP data appears on an existing connection after capture starts."""
        result = {"is_http": False, "type": "", "method": "", "path": "", "status": "", "reason": "", "headers": {}, "body": b""}
        try:
            if b"\r\n\r\n" not in raw:
                return result
            head, body = raw.split(b"\r\n\r\n", 1)
            first_line = head.split(b"\r\n", 1)[0]
            m_req = HTTP_METHOD_RE.match(first_line)
            m_res = HTTP_RESPONSE_RE.match(first_line)
            if m_req:
                result.update({"is_http": True, "type": "request", "method": m_req.group(1).decode('utf-8','ignore').upper(), "path": m_req.group(2).decode('utf-8','ignore')})
            elif m_res:
                result.update({"is_http": True, "type": "response", "status": m_res.group(1).decode('utf-8','ignore'), "reason": m_res.group(2).decode('utf-8','ignore')})
            else:
                return result
            result["headers"] = parse_http_headers_from_raw(raw)
            result["body"] = body
        except Exception:
            pass
        return result

    # TLS ClientHello se SNI hostname nikalta hai; content decrypt nahi hota, only metadata.
    def extract_tls_sni(self, packet):
        try:
            if packet.haslayer(TLSClientHello):
                hello = packet[TLSClientHello]
                for ext in getattr(hello, "ext", []):
                    if isinstance(ext, TLS_Ext_ServerName):
                        names = getattr(ext, "servernames", [])
                        if names:
                            name = names[0].servername
                            return name.decode("utf-8", "ignore") if isinstance(name, bytes) else str(name)
        except Exception:
            return ""
        return ""

    # Main packet parser: har captured packet ka protocol, ports, headers, HTTP fields aur details prepare karta hai.
    def analyze_packet(self, packet):
        if not packet.haslayer(IP):
            return
        try:
            now = datetime.now()
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
            dst_display, dst_domain = self.resolve_display(dst_ip)
            src_port = dst_port = ""
            base_protocol = "OTHER"
            details = f"Length={packet[IP].len}"

            if packet.haslayer(TCP):
                base_protocol = "TCP"
                src_port, dst_port = str(packet[TCP].sport), str(packet[TCP].dport)
                details = f"Flags={packet[TCP].flags} Seq={packet[TCP].seq} Ack={packet[TCP].ack} Win={packet[TCP].window} Len={packet[IP].len}"
            elif packet.haslayer(UDP):
                base_protocol = "UDP"
                src_port, dst_port = str(packet[UDP].sport), str(packet[UDP].dport)
                details = f"UDP Len={packet[UDP].len} Packet Len={packet[IP].len}"
            elif packet.haslayer(ICMP):
                base_protocol = "ICMP"
                details = f"Type={packet[ICMP].type} Code={packet[ICMP].code} Len={packet[IP].len}"

            app_protocol = self.detect_application_protocol(packet, base_protocol)
            tls_sni = self.extract_tls_sni(packet)
            if tls_sni:
                dst_domain = tls_sni
                dst_display = f"{dst_ip} [{tls_sni}]"

            header_summary = []
            if packet.haslayer(Ether):
                header_summary.append(
                    "=== LAYER 2: ETHERNET ===\n"
                    f"Destination MAC : {packet[Ether].dst}\n"
                    f"Source MAC      : {packet[Ether].src}\n"
                    f"EtherType       : {hex(packet[Ether].type)}\n"
                )
            header_summary.append(
                "=== LAYER 3: IPv4 ===\n"
                f"Capture Date    : {now.strftime('%Y-%m-%d')}\n"
                f"Capture Time    : {now.strftime('%H:%M:%S.%f')[:-3]}\n"
                f"Source IP       : {src_ip}\n"
                f"Destination IP  : {dst_ip}\n"
                f"Destination DNS : {dst_domain or 'N/A'}\n"
                f"TTL             : {packet[IP].ttl}\n"
                f"Total Length    : {packet[IP].len} bytes\n"
                f"Protocol Number : {packet[IP].proto}\n"
                f"Checksum        : {hex(packet[IP].chksum)}\n"
            )
            if packet.haslayer(TCP):
                header_summary.append(
                    "=== LAYER 4: TCP ===\n"
                    f"Source Port     : {src_port}\n"
                    f"Destination Port: {dst_port}\n"
                    f"Flags           : {packet[TCP].flags}\n"
                    f"Window Size     : {packet[TCP].window}\n"
                    f"Checksum        : {hex(packet[TCP].chksum)}\n"
                )
            elif packet.haslayer(UDP):
                header_summary.append(
                    "=== LAYER 4: UDP ===\n"
                    f"Source Port     : {src_port}\n"
                    f"Destination Port: {dst_port}\n"
                    f"Length          : {packet[UDP].len}\n"
                    f"Checksum        : {hex(packet[UDP].chksum)}\n"
                )
            elif packet.haslayer(ICMP):
                header_summary.append(
                    "=== LAYER 4: ICMP ===\n"
                    f"Type            : {packet[ICMP].type}\n"
                    f"Code            : {packet[ICMP].code}\n"
                )

            if packet.haslayer(DNS):
                qname = ""
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname.decode("utf-8", "ignore").rstrip(".")
                header_summary.append("=== DNS DETAILS ===\n" + f"Query Name      : {qname or 'N/A'}\n")

            http_event_lines = []
            is_http_request = packet.haslayer(HTTPRequest)
            if is_http_request:
                host = packet[HTTPRequest].Host.decode("utf-8", "ignore") if packet[HTTPRequest].Host else dst_domain
                method = packet[HTTPRequest].Method.decode("utf-8", "ignore") if packet[HTTPRequest].Method else ""
                path = packet[HTTPRequest].Path.decode("utf-8", "ignore") if packet[HTTPRequest].Path else ""
                headers = http_headers_from_request(packet)
                header_summary.append(
                    "=== HTTP REQUEST DETAILS ===\n"
                    f"Method          : {method}\n"
                    f"Host            : {host}\n"
                    f"Path            : {path}\n"
                    f"User-Agent      : {headers.get('User-Agent', 'N/A')}\n"
                    f"Content-Type    : {headers.get('Content-Type', 'N/A')}\n"
                    f"Content-Length  : {headers.get('Content-Length', 'N/A')}\n"
                )
                http_event_lines.append(f"[HTTP] {method} http://{host}{path} from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            if packet.haslayer(HTTPResponse):
                status = getattr(packet[HTTPResponse], "Status_Code", b"")
                reason = getattr(packet[HTTPResponse], "Reason_Phrase", b"")
                status = status.decode("utf-8", "ignore") if isinstance(status, bytes) else str(status)
                reason = reason.decode("utf-8", "ignore") if isinstance(reason, bytes) else str(reason)
                header_summary.append("=== HTTP RESPONSE DETAILS ===\n" + f"Status          : {status} {reason}\n")
                http_event_lines.append(f"[HTTP-RESPONSE] {src_ip}:{src_port} -> {dst_ip}:{dst_port} Status={status} {reason}")

            if packet.haslayer(Raw):
                raw = bytes(packet[Raw].load)
                decoded = "".join(chr(b) if 32 <= b <= 126 or b in [10, 13, 9] else "." for b in raw)
                header_summary.append("=== PAYLOAD PREVIEW ===\n" + decoded[:1200] + "\n")
                header_summary.append("=== RAW HEX VIEW (FIRST 256 BYTES) ===\n" + hexdump(raw[:256], dump=True))

                # Flow buffering fixes the case where a website was already open before capture starts.
                # The tool cannot recover old packets, but it will capture any new HTTP request/response
                # data sent on the already-established TCP connection after START CAPTURE is clicked.
                if app_protocol in ["HTTP", "HTTP-ALT"]:
                    flow_key = self.build_flow_key(packet)
                    buf = (self.http_flow_buffers[flow_key] + raw)[-MAX_HTTP_FLOW_BUFFER:]
                    self.http_flow_buffers[flow_key] = buf
                    parsed_http = self.parse_raw_http_message(buf)
                    if parsed_http.get("is_http"):
                        headers_raw = parsed_http.get("headers", {})
                        host_raw = headers_raw.get("Host", dst_domain or dst_ip)
                        ctype_raw = headers_raw.get("Content-Type", "")
                        if parsed_http["type"] == "request":
                            method_raw, path_raw = parsed_http["method"], parsed_http["path"]
                            header_summary.append(
                                "=== HTTP RAW REQUEST DETECTED FROM LIVE TCP STREAM ===\n"
                                f"Method          : {method_raw}\n"
                                f"Host            : {host_raw}\n"
                                f"Path            : {path_raw}\n"
                                f"Content-Type    : {ctype_raw or 'N/A'}\n"
                                f"Content-Length  : {headers_raw.get('Content-Length', 'N/A')}\n"
                            )
                            http_event_lines.append(f"[HTTP-LIVE] {method_raw} http://{host_raw}{path_raw} from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                            query_fields = parse_query_fields(path_raw)
                            if query_fields:
                                q_text = "\n".join([f"  {k} = {v}" for k, v in query_fields])
                                header_summary.append("=== HTTP QUERY INPUT FIELDS ===\n" + q_text + "\n")
                                http_event_lines.append("[INPUT-FIELDS][QUERY]\n" + q_text)
                            if "application/x-www-form-urlencoded" in ctype_raw.lower() or (method_raw in ["POST", "PUT", "PATCH"] and b"=" in parsed_http.get("body", b"")[:4096]):
                                form_fields = parse_urlencoded_form(buf)
                                if form_fields:
                                    form_text = "\n".join([f"  {k} = {v}" for k, v in form_fields])
                                    header_summary.append("=== HTTP FORM INPUT FIELDS ===\n" + form_text + "\n")
                                    http_event_lines.append("[INPUT-FIELDS][FORM]\n" + form_text)
                            if "application/json" in ctype_raw.lower():
                                json_fields = parse_json_fields(buf)
                                if json_fields:
                                    json_text = "\n".join([f"  {k} = {v}" for k, v in json_fields])
                                    header_summary.append("=== HTTP JSON INPUT FIELDS ===\n" + json_text + "\n")
                                    http_event_lines.append("[INPUT-FIELDS][JSON]\n" + json_text)
                            if "multipart/form-data" in ctype_raw.lower():
                                fields, skipped_files = parse_multipart_fields(buf, ctype_raw)
                                if fields:
                                    form_text = "\n".join([f"  {k} = {v}" for k, v in fields])
                                    header_summary.append("=== MULTIPART FORM INPUT FIELDS ===\n" + form_text + "\n")
                                    http_event_lines.append("[MULTIPART-FORM] Fields:\n" + form_text)
                                if skipped_files:
                                    skipped_text = ", ".join(skipped_files[:10])
                                    header_summary.append("=== MULTIPART FILE PARTS DETECTED ===\nUploaded file parts were detected but file saving/export is disabled.\nFiles: " + skipped_text + "\n")
                                    http_event_lines.append("[MULTIPART-FILE-PART] File upload part detected; saving disabled. Files: " + skipped_text)
                        elif parsed_http["type"] == "response":
                            header_summary.append("=== HTTP RAW RESPONSE DETECTED FROM LIVE TCP STREAM ===\n" + f"Status          : {parsed_http['status']} {parsed_http['reason']}\n")
                            http_event_lines.append(f"[HTTP-RESPONSE-LIVE] {src_ip}:{src_port} -> {dst_ip}:{dst_port} Status={parsed_http['status']} {parsed_http['reason']}")

                if is_http_request:
                    headers = http_headers_from_request(packet)
                    ctype = headers.get("Content-Type", "")
                    method = packet[HTTPRequest].Method.decode("utf-8", "ignore") if packet[HTTPRequest].Method else ""
                    path_for_query = packet[HTTPRequest].Path.decode("utf-8", "ignore") if packet[HTTPRequest].Path else ""
                    query_fields = parse_query_fields(path_for_query)
                    if query_fields:
                        q_text = "\n".join([f"  {k} = {v}" for k, v in query_fields])
                        header_summary.append("=== HTTP QUERY INPUT FIELDS ===\n" + q_text + "\n")
                        http_event_lines.append("[INPUT-FIELDS][QUERY]\n" + q_text)
                    if "application/x-www-form-urlencoded" in ctype.lower() or (method in ["POST", "PUT", "PATCH"] and b"=" in raw and b"&" in raw[:2048]):
                        form_fields = parse_urlencoded_form(raw)
                        if form_fields:
                            form_text = "\n".join([f"  {k} = {v}" for k, v in form_fields])
                            header_summary.append("=== HTTP FORM INPUT FIELDS ===\n" + form_text + "\n")
                            http_event_lines.append("[INPUT-FIELDS][FORM]\n" + form_text)
                    if "application/json" in ctype.lower():
                        json_fields = parse_json_fields(raw)
                        if json_fields:
                            json_text = "\n".join([f"  {k} = {v}" for k, v in json_fields])
                            header_summary.append("=== HTTP JSON INPUT FIELDS ===\n" + json_text + "\n")
                            http_event_lines.append("[INPUT-FIELDS][JSON]\n" + json_text)
                    if "multipart/form-data" in ctype.lower():
                        fields, skipped_files = parse_multipart_fields(raw, ctype)
                        if fields:
                            form_text = "\n".join([f"  {k} = {v}" for k, v in fields])
                            header_summary.append("=== MULTIPART FORM INPUT FIELDS ===\n" + form_text + "\n")
                            http_event_lines.append("[MULTIPART-FORM] Fields:\n" + form_text)
                        if skipped_files:
                            skipped_text = ", ".join(skipped_files[:10])
                            header_summary.append("=== MULTIPART FILE PARTS DETECTED ===\nUploaded file parts were detected but file saving/export is disabled.\nFiles: " + skipped_text + "\n")
                            http_event_lines.append("[MULTIPART-FILE-PART] File upload part detected; saving disabled. Files: " + skipped_text)

            for line in http_event_lines:
                self.alert_signal.emit(line)

            self.packet_signal.emit({
                "Date": now.strftime("%Y-%m-%d"),
                "Time": now.strftime("%H:%M:%S.%f")[:-3],
                "Src_IP": src_ip,
                "Src_Port": src_port,
                "Dst_IP": dst_display,
                "Dst_Raw_IP": dst_ip,
                "Dst_Port": dst_port,
                "Protocol": base_protocol,
                "App_Protocol": app_protocol,
                "Length": str(packet[IP].len),
                "Domain": dst_domain,
                "Details": details,
                "Parsed_Headers": "\n".join(header_summary),
                "SearchText": f"{src_ip} {src_port} {dst_ip} {dst_port} {dst_domain} {base_protocol} {app_protocol} {details}".lower()
            })
        except Exception as e:
            self.alert_signal.emit(f"[!] Packet parse error: {str(e)}")

# =============================================================================
# NetworkScanner Thread
# Local subnet me ARP scan karke connected devices ka IP, MAC, hostname/vendor collect karta hai.
# =============================================================================
class NetworkScanner(QThread):
    scan_signal = pyqtSignal(str)
    device_signal = pyqtSignal(dict)
    # Scanner object selected interface ke liye initialize hota hai.
    def __init__(self, iface):
        super().__init__()
        self.iface = iface

    # ARP scan run karta hai aur active devices GUI ko signal ke through bhejta hai.
    def run(self):
        try:
            ip_range = self.guess_subnet()
            self.scan_signal.emit(f"[*] Scanning local subnet: {ip_range}\n")
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=3,
                         iface=self.iface, verbose=0)[0]
            self.scan_signal.emit(f"[+] Active devices found: {len(result)}\n" + "=" * 70)
            for _, received in result:
                mac, ip = received.hwsrc, received.psrc
                try:
                    vendor = conf.manufdb._resolve_MAC(mac)
                except Exception:
                    vendor = "Unknown"
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except Exception:
                    name = "Hidden/No reverse DNS"
                dev = {"ip": ip, "mac": mac, "name": name, "vendor": vendor}
                self.device_signal.emit(dev)
                self.scan_signal.emit(f"IP: {ip:<15} | MAC: {mac}\nHostname: {name}\nVendor  : {vendor}\n" + "-" * 70)
            self.scan_signal.emit("\n[✓] Device discovery completed.")
        except Exception as e:
            self.scan_signal.emit(f"[!] Device scan error: {str(e)}")
    
    # Current routing table se subnet guess karta hai. Fallback 192.168.1.0/24 hai.
    def guess_subnet(self):
        for net, msk, gw, iface, addr, metric in conf.route.routes:
            if iface == self.iface and addr and net not in [0, 4294967295]:
                try:
                    ip = ipaddress.ip_address(addr)
                    if ip.version == 4:
                        parts = addr.split(".")
                        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                except Exception:
                    pass
        return "192.168.1.0/24"

# =============================================================================
# MonitorDashboard GUI
# Main PyQt6 window: tabs, live packet table, HTTP events, device scan, statistics aur PDF export.
# =============================================================================
class MonitorDashboard(QMainWindow):
    # Main dashboard initialize: window branding, counters, caches aur tabs setup hote hain.
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{TOOL_NAME} | By {AUTHOR_NAME}")
        self.setGeometry(80, 70, 1550, 920)
        self.setStyleSheet("background-color: #0b0f19; color: #ffffff;")
        self.captured_packets = []
        self.devices = []
        self.alerts_cache = []
        self.protocol_counter = Counter()
        self.app_counter = Counter()
        self.src_counter = Counter()
        self.dst_counter = Counter()
        self.http_event_counter = Counter()
        self.init_ui()
        self.fetch_network_ips()

    # Status bar me local/public IP show karne ki try karta hai. Offline mode me graceful fallback hai.
    def fetch_network_ips(self):
        def get_ip():
            try:
                pub_ip = requests.get("https://api.ipify.org", timeout=4).text
                local_ip = socket.gethostbyname(socket.gethostname())
                self.statusBar().showMessage(f"{TOOL_NAME} | Author: {AUTHOR_NAME} | Local IP: {local_ip} | Public IP: {pub_ip}")
            except Exception:
                self.statusBar().showMessage(f"{TOOL_NAME} | Author: {AUTHOR_NAME} | Offline/Local Mode")
            self.statusBar().setStyleSheet("color: #00ffcc; font-weight: bold; font-family: Consolas;")
        threading.Thread(target=get_ip, daemon=True).start()

    # Main GUI tabs create karta hai: live inspector, HTTP events, devices, statistics.
    def init_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        self.tabs = QTabWidget(); main_layout.addWidget(self.tabs)
        self.tab_monitor = QWidget(); self.setup_monitor_tab(); self.tabs.addTab(self.tab_monitor, "Live Packet Inspector")
        self.tab_alerts = QWidget(); self.setup_alerts_tab(); self.tabs.addTab(self.tab_alerts, "HTTP / Form Events")
        self.tab_devices = QWidget(); self.setup_devices_tab(); self.tabs.addTab(self.tab_devices, "Network Devices")
        self.tab_stats = QWidget(); self.setup_stats_tab(); self.tabs.addTab(self.tab_stats, "Live Statistics")

    # Live Packet Inspector tab: interface selector, capture buttons, filter bar, packet table aur details pane.
    def setup_monitor_tab(self):
        layout = QVBoxLayout(self.tab_monitor)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("<b>NETWORK INTERFACE:</b>"))
        self.iface_dropdown = QComboBox()
        self.iface_dropdown.addItems([iface.name for iface in get_working_ifaces()])
        self.iface_dropdown.setStyleSheet("background-color:#1f2937;padding:10px;border-radius:4px;font-weight:bold;min-width:220px;")
        controls.addWidget(self.iface_dropdown)
        self.btn_start = self.create_btn("START CAPTURE", "#00ffcc")
        self.btn_stop = self.create_btn("STOP CAPTURE", "#ff3366")
        self.btn_pdf = self.create_btn("EXPORT PDF REPORT", "#3b82f6")
        self.btn_stop.setEnabled(False)
        self.btn_start.clicked.connect(self.start_sniffing); self.btn_stop.clicked.connect(self.stop_sniffing); self.btn_pdf.clicked.connect(self.generate_pdf_report)
        controls.addWidget(self.btn_start); controls.addWidget(self.btn_stop); controls.addWidget(self.btn_pdf)
        layout.addLayout(controls)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("<b>PACKET FILTER:</b>"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Examples: ip==192.168.1.5 | proto==tcp | app==dns | port==443 | domain contains google | src==192.168.1.4 && app==http")
        self.filter_input.setStyleSheet("background:#020617;color:#e5e7eb;padding:10px;font-family:Consolas;border:1px solid #334155;border-radius:4px;")
        self.filter_input.textChanged.connect(self.apply_filter)
        filter_row.addWidget(self.filter_input)
        self.filter_status = QLabel("Showing all packets")
        filter_row.addWidget(self.filter_status)
        layout.addLayout(filter_row)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["Date", "Time", "Source IP", "Src Port", "Destination", "Dst Port", "Protocol", "App", "Length"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setStyleSheet("QTableWidget{background:#0f172a;gridline-color:#334155;font-family:Consolas;font-size:12px;} QHeaderView::section{background:#1e293b;color:#38bdf8;padding:8px;font-weight:bold;} QTableWidget::item:selected{background:#0ea5e9;color:white;}")
        self.table.itemSelectionChanged.connect(self.display_packet_headers)
        splitter.addWidget(self.table)
        self.packet_details = QTextEdit(); self.packet_details.setReadOnly(True)
        self.packet_details.setStyleSheet("background:#020617;color:#4ade80;font-family:Consolas;font-size:13px;border:2px solid #334155;padding:12px;")
        self.packet_details.setPlaceholderText("Select any packet to view decoded headers, payload preview and short hex view. Existing website sessions are captured from new packets after START CAPTURE.")
        splitter.addWidget(self.packet_details)
        layout.addWidget(splitter)

    # HTTP/Form Events tab: plaintext HTTP requests/forms ke summary logs yahan show hote hain.
    def setup_alerts_tab(self):
        layout = QVBoxLayout(self.tab_alerts)
        layout.addWidget(QLabel("<b style='color:#fbbf24;'>Realtime HTTP request summaries and input/form fields. Uploaded file contents are not saved or exported.</b>"))
        self.http_log = QTextEdit(); self.http_log.setReadOnly(True)
        self.http_log.setStyleSheet("background:#000;color:#fbbf24;font-family:Consolas;font-size:13px;padding:12px;border:1px solid #334155;")
        layout.addWidget(self.http_log)

    # Network Devices tab: ARP scan button aur device discovery log area.
    def setup_devices_tab(self):
        layout = QVBoxLayout(self.tab_devices)
        btn = self.create_btn("SCAN CONNECTED DEVICES", "#a855f7"); btn.clicked.connect(self.run_scanner)
        layout.addWidget(btn)
        self.device_log = QTextEdit(); self.device_log.setReadOnly(True)
        self.device_log.setStyleSheet("background:#000;color:#a855f7;font-family:Consolas;font-size:13px;padding:12px;border:1px solid #334155;")
        layout.addWidget(self.device_log)

    # Live Statistics tab: total packets, protocol counters, HTTP counters aur top sources show karta hai....
    def setup_stats_tab(self):
        layout = QVBoxLayout(self.tab_stats)
        self.stats_box = QTextEdit(); self.stats_box.setReadOnly(True)
        self.stats_box.setStyleSheet("background:#020617;color:#93c5fd;font-family:Consolas;font-size:14px;padding:15px;border:1px solid #334155;")
        layout.addWidget(self.stats_box)
        self.refresh_stats()

    # Reusable styled button helper, taaki UI buttons consistent look me rahein
    def create_btn(self, text, color):
        btn = QPushButton(text)
        btn.setStyleSheet(f"QPushButton{{border:2px solid {color};color:{color};background:rgba(0,0,0,.4);font-weight:bold;padding:12px 20px;border-radius:8px;}} QPushButton:hover{{background:{color};color:#000;}} QPushButton:disabled{{border:2px solid #475569;color:#475569;}}"); return btn

    # Start Capture button handler: selected interface par PacketSniffer thread start karta hai.
    def start_sniffing(self):
        iface = self.iface_dropdown.currentText()
        if not iface: return
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True); self.iface_dropdown.setEnabled(False)
        self.sniffer = PacketSniffer(iface)
        self.sniffer.packet_signal.connect(self.update_table)
        self.sniffer.alert_signal.connect(self.add_alert)
        self.sniffer.start()
    
    # Stop Capture button handler: sniffer ko stop signal deta hai aur UI controls re-enable karta hai.
    def stop_sniffing(self):
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False); self.iface_dropdown.setEnabled(True)
        if hasattr(self, "sniffer"): self.sniffer.stop()

    # HTTP/form event log add karta hai aur event counters update karta hai.
    def add_alert(self, msg):
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        final = f"[{stamp}] {msg}"
        self.alerts_cache.append(final); self.http_log.append(final)
        if "[HTTP]" in msg or "[HTTP-LIVE]" in msg:
            self.http_event_counter["HTTP Requests"] += 1
        elif "[HTTP-RESPONSE]" in msg or "[HTTP-RESPONSE-LIVE]" in msg:
            self.http_event_counter["HTTP Responses"] += 1
        elif "[INPUT-FIELDS]" in msg or "[MULTIPART-FORM]" in msg:
            self.http_event_counter["HTTP Input/Form Fields"] += 1
        elif "[MULTIPART-FILE-PART]" in msg:
            self.http_event_counter["Multipart File Parts Detected"] += 1

    # New packet data receive hote hi table/counters/cache update karta hai
    def update_table(self, data):
        self.captured_packets.append(data)
        self.protocol_counter[data["Protocol"]] += 1
        self.app_counter[data["App_Protocol"]] += 1
        self.src_counter[data["Src_IP"]] += 1
        self.dst_counter[data["Dst_Raw_IP"]] += 1
        self.add_packet_row(data)
        if len(self.captured_packets) % 10 == 0: self.refresh_stats()
        if self.table.rowCount() > MAX_UI_ROWS: self.table.removeRow(0)
        self.table.scrollToBottom()

    # Packet dictionary ko GUI table row me convert karta hai.
    def add_packet_row(self, data):
        row = self.table.rowCount(); self.table.insertRow(row)
        keys = ["Date", "Time", "Src_IP", "Src_Port", "Dst_IP", "Dst_Port", "Protocol", "App_Protocol", "Length"]
        for i, key in enumerate(keys):
            item = QTableWidgetItem(data.get(key, "")); item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable); self.table.setItem(row, i, item)

    # Filter input ke according table ko rebuild karta hai. Original captured_packets safe rehta hai.
    def apply_filter(self):
        query = self.filter_input.text().strip().lower()
        self.table.setRowCount(0)
        shown = 0
        for pkt in self.captured_packets[-MAX_UI_ROWS:]:
            if self.packet_matches_filter(pkt, query):
                self.add_packet_row(pkt); shown += 1
        self.filter_status.setText(f"Showing {shown} / {len(self.captured_packets)} packets")

    # Simple filter engine: ip/proto/app/port/domain conditions match karta hai
    def packet_matches_filter(self, pkt, query):
        if not query: return True
        parts = [p.strip() for p in query.split("&&")]
        for part in parts:
            if "==" in part:
                field, value = [x.strip() for x in part.split("==", 1)]
                mapping = {
                    "ip": f"{pkt['Src_IP']} {pkt['Dst_Raw_IP']}", "src": pkt["Src_IP"], "dst": pkt["Dst_Raw_IP"],
                    "proto": pkt["Protocol"].lower(), "protocol": pkt["Protocol"].lower(), "app": pkt["App_Protocol"].lower(),
                    "port": f"{pkt['Src_Port']} {pkt['Dst_Port']}", "srcport": pkt["Src_Port"], "dstport": pkt["Dst_Port"],
                    "domain": pkt.get("Domain", "").lower()
                }
                
                target_val = mapping.get(field, "").lower()
                
                # FIX 1: Exact match for specific fields so 'app==http' does not match 'https'
                if field in ["app", "proto", "protocol", "src", "dst", "srcport", "dstport"]:
                    if value != target_val: 
                        return False
                else:
                    # 'ip' and 'port' contain both src and dst combined, so they still need 'in'
                    if value not in target_val: 
                        return False
                        
            elif " contains " in part:
                field, value = [x.strip() for x in part.split(" contains ", 1)]
                if field == "domain" and value not in pkt.get("Domain", "").lower(): return False
                elif field != "domain" and value not in pkt.get("SearchText", ""): return False
            else:
                # FIX 2: Exact word boundary match for global search (prevents 'http' from matching 'https')
                if not re.search(rf'\b{re.escape(part)}\b', pkt.get("SearchText", "")): 
                    return False
        return True

    # Selected table row ka decoded packet detail lower pane me show karta hai
    def display_packet_headers(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows: return
        row = rows[0].row()
        row_values = [self.table.item(row, i).text() if self.table.item(row, i) else "" for i in range(self.table.columnCount())]
        for pkt in reversed(self.captured_packets):
            if [pkt.get(k, "") for k in ["Date", "Time", "Src_IP", "Src_Port", "Dst_IP", "Dst_Port", "Protocol", "App_Protocol", "Length"]] == row_values:
                self.packet_details.setText(pkt.get("Parsed_Headers", "No details.")); break

    # Device scan start karta hai, previous device list clear karta hai.
    def run_scanner(self):
        iface = self.iface_dropdown.currentText(); self.device_log.clear(); self.devices.clear()
        self.scanner = NetworkScanner(iface)
        self.scanner.scan_signal.connect(lambda msg: self.device_log.append(msg))
        self.scanner.device_signal.connect(lambda dev: self.devices.append(dev))
        self.scanner.start()

    # Statistics text refresh karta hai: protocol totals, app totals, HTTP events, top sources.
    def refresh_stats(self):
        lines = [f"{TOOL_NAME}", f"Author: {AUTHOR_NAME}", "", f"Total captured packets: {len(self.captured_packets)}", f"Connected devices discovered: {len(self.devices)}", "", "Protocol totals:"]
        for k, v in self.protocol_counter.most_common(): lines.append(f"  {k:<12}: {v}")
        lines.append("\nApplication protocol totals:")
        for k, v in self.app_counter.most_common(): lines.append(f"  {k:<12}: {v}")
        lines.append("\nHTTP/Form event totals:")
        for k, v in self.http_event_counter.most_common(): lines.append(f"  {k:<22}: {v}")
        lines.append("\nTop source IP request/packet count:")
        for k, v in self.src_counter.most_common(10): lines.append(f"  {k:<18}: {v}")
        self.stats_box.setText("\n".join(lines))

    # PDF helper: page me space kam ho to new page add karta hai.
    def _pdf_check_page(self, pdf, needed=18):
        if pdf.get_y() + needed > 282:
            pdf.add_page()
    # PDF-safe text cleanup wrapper.
    def _pdf_clean(self, value, limit=None):
        return safe_text(value, limit)

    # PDF page header: dark banner, report title aur prepared-by line.
    def pdf_header(self, pdf, title="Network Monitoring Report"):
        pdf.set_fill_color(15, 23, 42)
        pdf.rect(0, 0, 210, 30, "F")
        pdf.set_xy(10, 8)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 7, self._pdf_clean(title.upper(), 80), ln=True, align="C")
        pdf.set_font("Arial", "", 9)
        pdf.cell(0, 6, self._pdf_clean(f"{TOOL_NAME} | Prepared by {AUTHOR_NAME}", 100), ln=True, align="C")
        pdf.set_text_color(0, 0, 0)
        pdf.set_y(38)

    # PDF footer note: authorized monitoring/reporting reminder.
    def pdf_footer_note(self, pdf):
        pdf.set_y(-12)
        pdf.set_font("Arial", "I", 7)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, self._pdf_clean(f"Generated by {TOOL_NAME} - Authorized monitoring/reporting use only", 110), align="C")
        pdf.set_text_color(0, 0, 0)

    # PDF section heading helper with optional subtitle/description.
    def pdf_section(self, pdf, title, subtitle=None):
        self._pdf_check_page(pdf, 16)
        pdf.ln(3)
        pdf.set_font("Arial", "B", 12)
        pdf.set_fill_color(30, 41, 59)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 8, self._pdf_clean(title, 90), ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        if subtitle:
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(71, 85, 105)
            pdf.multi_cell(0, 5, self._pdf_clean(subtitle, 350))
            pdf.set_text_color(0, 0, 0)
        pdf.ln(1)

    # PDF paragraph writer with wrapping.
    def pdf_paragraph(self, pdf, text, size=9):
        self._pdf_check_page(pdf, 12)
        pdf.set_font("Arial", "", size)
        pdf.multi_cell(0, 5.5, self._pdf_clean(text))
        pdf.ln(1)

    # PDF metric table helper: label/value rows ke liye.
    def pdf_key_value_table(self, pdf, rows, left_width=75, right_width=45):
        self._pdf_check_page(pdf, 14)
        pdf.set_font("Arial", "B", 8)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(left_width, 7, "Metric", border=1, fill=True)
        pdf.cell(right_width, 7, "Value", border=1, ln=True, fill=True)
        pdf.set_font("Arial", "", 8)
        for label, val in rows:
            self._pdf_check_page(pdf, 8)
            pdf.cell(left_width, 6, self._pdf_clean(label, 45), border=1)
            pdf.cell(right_width, 6, self._pdf_clean(val, 32), border=1, ln=True)
        pdf.ln(2)

    # PDF bar chart helper: Counter data ko simple horizontal bars me draw karta hai.
    def draw_bar_chart(self, pdf, title, counter, max_items=10):
        self._pdf_check_page(pdf, 18)
        pdf.set_font("Arial", "B", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 7, self._pdf_clean(title, 80), ln=True)
        pdf.set_text_color(0, 0, 0)
        if not counter:
            pdf.set_font("Arial", "", 8)
            pdf.cell(0, 6, "No data available.", ln=True)
            return
        items = counter.most_common(max_items)
        max_val = max(v for _, v in items) or 1
        total = sum(counter.values()) or 1
        label_x, bar_x, value_x = 12, 66, 176
        y = pdf.get_y() + 1
        for label, val in items:
            if y > 264:
                pdf.add_page(); self.pdf_header(pdf, "Report Continued"); y = pdf.get_y()
            pct = (val / total) * 100
            bar_w = max(3, int((val / max_val) * 105))
            pdf.set_xy(label_x, y)
            pdf.set_font("Arial", "", 7.5)
            pdf.cell(52, 5, self._pdf_clean(label, 30))
            pdf.set_xy(bar_x, y + 0.7)
            pdf.set_fill_color(59, 130, 246)
            pdf.cell(bar_w, 4, "", fill=True)
            pdf.set_xy(value_x, y)
            pdf.set_font("Arial", "", 7)
            pdf.cell(25, 5, f"{val} ({pct:.1f}%)")
            y += 6.8
        pdf.set_y(y + 3)

    # PDF counter table: protocol/source/destination counters ko count + percentage ke sath show karta hai.
    def pdf_counter_table(self, pdf, title, counter, max_items=15, explain=None):
        self.pdf_section(pdf, title, explain)
        if not counter:
            self.pdf_paragraph(pdf, "No data available for this section.", 8)
            return
        pdf.set_font("Arial", "B", 8)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(95, 7, "Item", border=1, fill=True)
        pdf.cell(25, 7, "Count", border=1, fill=True)
        pdf.cell(35, 7, "Share", border=1, ln=True, fill=True)
        pdf.set_font("Arial", "", 8)
        total = sum(counter.values()) or 1
        for label, count in counter.most_common(max_items):
            self._pdf_check_page(pdf, 8)
            pdf.cell(95, 6, self._pdf_clean(label, 55), border=1)
            pdf.cell(25, 6, str(count), border=1)
            pdf.cell(35, 6, f"{(count/total)*100:.1f}%", border=1, ln=True)
        pdf.ln(2)
    # Non-technical readers ke liye packet table fields ka meaning explain karta hai
    def pdf_field_dictionary(self, pdf):
        self.pdf_section(pdf, "Field Dictionary for Non-Technical Readers", "This section explains the packet-table columns in simple language.")
        rows = [
            ("Date / Time", "When the packet was captured by this tool."),
            ("Source IP", "The device address that sent the packet."),
            ("Source Port", "The sending app/service number on the source device."),
            ("Destination IP", "The device/server address that received the packet."),
            ("Destination Port", "The receiving app/service number such as 80 for HTTP or 443 for HTTPS."),
            ("Protocol", "The transport/network protocol, for example TCP, UDP, ICMP."),
            ("Application", "The likely application protocol, for example DNS, HTTP, HTTPS/TLS, SSH, SMB."),
            ("Length", "Packet size in bytes. Larger values usually mean more data was carried."),
            ("Domain", "Readable website/server name when DNS reverse lookup or TLS SNI is available."),
        ]
        pdf.set_font("Arial", "B", 8)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(42, 7, "Field", border=1, fill=True)
        pdf.cell(148, 7, "Meaning", border=1, ln=True, fill=True)
        pdf.set_font("Arial", "", 8)
        
        for k, v in rows:
            self._pdf_check_page(pdf, 8)
            # Print the left column
            pdf.cell(42, 6, self._pdf_clean(k, 24), border=1)
            
            # FIX: Use cell() with ln=True instead of multi_cell() 
            # This ensures the cursor properly drops to the next line and resets to the left margin.
            pdf.cell(148, 6, self._pdf_clean(v, 120), border=1, ln=True)

    # Latest packet flow rows ko PDF table me write karta hai
    def pdf_packet_flow_table(self, pdf, packets, limit=350):
        self.pdf_section(pdf, "Captured Packet Flow Table", "Latest packet records are shown in source-to-destination format. This helps identify which device communicated with which server/service.")
        widths = [18, 21, 31, 14, 44, 14, 16, 19, 13]
        headers = ["Date", "Time", "Source IP", "SPort", "Destination", "DPort", "Proto", "App", "Bytes"]
        pdf.set_font("Arial", "B", 6.8)
        pdf.set_fill_color(226, 232, 240)
        for h, w in zip(headers, widths):
            pdf.cell(w, 6, h, border=1, fill=True)
        pdf.ln()
        pdf.set_font("Arial", "", 5.8)
        for pkt in packets[-limit:]:
            self._pdf_check_page(pdf, 7)
            vals = [pkt.get("Date", ""), pkt.get("Time", ""), pkt.get("Src_IP", ""), pkt.get("Src_Port", ""), pkt.get("Dst_IP", ""), pkt.get("Dst_Port", ""), pkt.get("Protocol", ""), pkt.get("App_Protocol", ""), pkt.get("Length", "")]
            for val, w in zip(vals, widths):
                pdf.cell(w, 5, self._pdf_clean(val, 34), border=1)
            pdf.ln()
        if len(packets) > limit:
            pdf.ln(2)
            pdf.set_font("Arial", "I", 8)
            pdf.multi_cell(0, 5, f"Note: PDF shows latest {limit} rows for readability. Total captured packets: {len(packets)}.")

    # Main PDF export function: overview, summary, charts, devices, HTTP events, packet flow aur conclusion generate karta hai.
    def generate_pdf_report(self):
        if not self.captured_packets:
            QMessageBox.warning(self, "No Data", "Capture packets before generating report."); return
        try:
            now = datetime.now()
            path = os.path.join(EXPORT_DIR, f"Professional_Network_Report_{now.strftime('%Y%m%d_%H%M%S')}.pdf")
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            self.pdf_header(pdf, "Professional Network Monitoring Report")

            self.pdf_section(pdf, "1. Tool Overview")
            self.pdf_paragraph(pdf,
                f"{TOOL_NAME} is designed for network administrators and security professionals to monitor and analyze network activity. "
                "It captures live network traffic, detailing source and destination IPs, ports, and protocols—such as HTTP, DNS, and SSH. "
                "While encrypted traffic remains secure, the tool still provides essential metadata, making it ideal for identifying active devices, monitoring network events, and generating clear, actionable reports for network oversight and forensic assessments."
            )

            self.pdf_section(pdf, "2. Executive Summary", "This summary highlights key metrics from the session, including the number of packets, active devices, unique source and destination IPs, and the most active applications. It offers a quick overview for both technical and non-technical readers to assess the network activity at a glance.")
            most_app = self.app_counter.most_common(1)[0][0] if self.app_counter else "N/A"
            most_src = self.src_counter.most_common(1)[0][0] if self.src_counter else "N/A"
            most_dst = self.dst_counter.most_common(1)[0][0] if self.dst_counter else "N/A"
            self.pdf_key_value_table(pdf, [
                ("Report generated", now.strftime('%Y-%m-%d %H:%M:%S')),
                ("Total packets captured", len(self.captured_packets)),
                ("Devices discovered", len(self.devices)),
                ("Unique source IPs", len(self.src_counter)),
                ("Unique destination IPs", len(self.dst_counter)),
                ("Most common application", most_app),
                ("Most active source IP", most_src),
                ("Most contacted destination IP", most_dst),
            ], 82, 60)

            self.pdf_field_dictionary(pdf)

            pdf.add_page(); self.pdf_header(pdf, "Traffic Analysis")
            self.pdf_counter_table(pdf, "3. Network Protocol Summary", self.protocol_counter, explain="Shows base protocols such as TCP, UDP, and ICMP. TCP is common for web browsing and login sessions; UDP is common for DNS/video/streaming; ICMP is often used for ping/network checks.")
            self.draw_bar_chart(pdf, "Network Protocol Distribution Graph", self.protocol_counter)
            self.pdf_counter_table(pdf, "4. Application Protocol Summary", self.app_counter, explain="This section summarizes the application protocols observed during the capture session. The table and graph below show the total number of packets and their percentage share for each detected protocol, providing a quick overview of the most active network services and communication patterns within the monitored network.")
            self.draw_bar_chart(pdf, "Application Protocol Distribution Graph", self.app_counter)

            pdf.add_page(); self.pdf_header(pdf, "Top Talkers")
            self.pdf_counter_table(pdf, "5. Top Source IP Addresses", self.src_counter, explain="These are the devices that sent the most packets during the capture.")
            self.draw_bar_chart(pdf, "Top Source IP Graph", self.src_counter)
            self.pdf_counter_table(pdf, "6. Top Destination IP Addresses", self.dst_counter, explain="These are the devices or servers that received the most packets during the capture.")
            self.draw_bar_chart(pdf, "Top Destination IP Graph", self.dst_counter)

            pdf.add_page(); self.pdf_header(pdf, "Devices and HTTP Events")
            self.pdf_section(pdf, "7. Connected Devices")
            pdf.set_font("Arial", "B", 7.5)
            pdf.set_fill_color(226, 232, 240)
            for h, w in [("IP Address", 34), ("MAC Address", 43), ("Hostname", 55), ("Vendor", 58)]:
                pdf.cell(w, 7, h, border=1, fill=True)
            pdf.ln(); pdf.set_font("Arial", "", 6.8)
            if self.devices:
                for d in self.devices:
                    self._pdf_check_page(pdf, 8)
                    pdf.cell(34, 6, self._pdf_clean(d.get("ip", ""), 18), border=1)
                    pdf.cell(43, 6, self._pdf_clean(d.get("mac", ""), 20), border=1)
                    pdf.cell(55, 6, self._pdf_clean(d.get("name", ""), 32), border=1)
                    pdf.cell(58, 6, self._pdf_clean(d.get("vendor", ""), 34), border=1)
                    pdf.ln()
            else:
                pdf.set_font("Arial", "", 8)
                pdf.multi_cell(0, 6, "Device scan was not run before report generation, so no connected-device list is available.", border=1)

            self.pdf_counter_table(pdf, "8. HTTP/Form Event Summary", self.http_event_counter, max_items=10, explain="Plaintext HTTP activity appears only when traffic is not encrypted and was visible during capture. HTTPS content stays encrypted.")

            self.pdf_section(pdf, "9. Recent HTTP/Form Events")
            pdf.set_font("Arial", "", 7.3)
            if self.alerts_cache:
                for log in self.alerts_cache[-90:]:
                    self._pdf_check_page(pdf, 8)
                    pdf.multi_cell(0, 4.5, self._pdf_clean(log.replace("\n", " "), 210))
                    pdf.ln(0.5)
            else:
                self.pdf_paragraph(pdf, "No plaintext HTTP/form events were recorded during this capture.", 8)

            pdf.add_page(); self.pdf_header(pdf, "Packet Flow")
            self.pdf_packet_flow_table(pdf, self.captured_packets, 350)

            pdf.add_page(); self.pdf_header(pdf, "Conclusion")
            self.pdf_section(pdf, "10. Professional Interpretation")
            self.pdf_paragraph(pdf,
                "This report provides a comprehensive overview of network activity captured during the monitoring session. The information presented should be interpreted as a traffic analysis summary rather than definitive proof of malicious activity. High packet counts from a particular source or destination may indicate increased network usage, but they should always be evaluated in the context of normal network behavior. "
                "The tool can assist network administrators, security professionals, and forensic analysts in identifying unusual traffic patterns, unauthorized devices, excessive requests, suspicious external connections, or potential attacks such as brute-force attempts and denial-of-service (DoS) activities. By monitoring live packet flows, HTTP events, connected devices, and protocol statistics, users can gain better visibility into network operations and investigate anomalies more effectively. "
                "While encrypted protocols such as HTTPS and SSH cannot be decrypted without appropriate keys, the captured metadata—including IP addresses, ports, domains, protocol types, and traffic volume—remains valuable for security monitoring and incident investigation. This report should therefore be used as a supporting document for network monitoring, security assessments, and forensic analysis in authorized environments."
            )
            self.pdf_footer_note(pdf)

            pdf.output(path)
            QMessageBox.information(self, "Report Exported", f"Professional PDF report saved successfully:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"PDF report error:\n{str(e)}")

# =============================================================================
# Application entry point
# Admin/root privilege warning ke baad PyQt application start hoti hai.
# =============================================================================
if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("\n[!] Administrator/root privileges are required for packet capture.")
        print("    Linux: sudo python3 netsight_mon.py")
        print("    Windows: run terminal as Administrator with Npcap installed.\n")
    app = QApplication(sys.argv)
    window = MonitorDashboard()
    window.show()
    sys.exit(app.exec())
