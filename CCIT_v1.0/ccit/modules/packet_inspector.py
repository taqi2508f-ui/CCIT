"""
CCIT Packet Inspector Module
Analyzes captured or simulated packet data for suspicious traffic patterns.
Performs protocol identification, payload scanning, and anomaly detection.
Custom-built — no Scapy or Wireshark clones.
"""

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


PROTOCOL_MAP = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    47:  "GRE",
    50:  "ESP (IPSec)",
    51:  "AH (IPSec)",
    88:  "EIGRP",
    89:  "OSPF",
    132: "SCTP",
}

PORT_SERVICE_MAP = {
    20: "FTP-Data",  21: "FTP",   22: "SSH",  23: "Telnet",
    25: "SMTP",      53: "DNS",   80: "HTTP", 110: "POP3",
    143: "IMAP",    443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S",  1433: "MSSQL",3306: "MySQL",3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
    4444: "Metasploit", 6666: "IRC", 6667: "IRC", 9090: "Proxy",
}

SUSPICIOUS_PAYLOAD_PATTERNS = [
    (rb"(?:CONNECT|GET|POST)\s+https?://", "HTTP proxy tunneling"),
    (rb"NICK\s+\w+\r\nUSER\s+", "IRC bot communication"),
    (rb"[\x00-\x1f]{20,}", "Binary shellcode padding"),
    (rb"\x90{10,}", "NOP sled (shellcode indicator)"),
    (rb"(?:cmd\.exe|powershell|/bin/sh|/bin/bash)", "Shell command in payload"),
    (rb"(?:eval|exec|system|passthru)\s*\(", "Code execution attempt"),
    (rb"(?:UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO\s+\w+\s+VALUES)", "SQL injection"),
    (rb"<script[^>]*>.*?alert\s*\(", "XSS payload"),
    (rb"(?:\.\./){3,}", "Path traversal attempt"),
    (rb"(?:etc/passwd|etc/shadow|win\.ini|system32)", "Sensitive file access attempt"),
]

C2_BEACON_PATTERNS = [
    rb"(?:GET|POST)\s+/(?:beacon|gate|check|ping|update|report)\s+HTTP/",
    rb"X-Session-Token:\s+[A-Za-z0-9+/=]{20,}",
    rb"Cookie:\s+[A-Za-z0-9]{32,}",
    rb"Content-Type:\s+application/x-www-form-urlencoded.*?data=[A-Za-z0-9+/=]{40,}",
]


@dataclass
class PacketInfo:
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "UNKNOWN"
    payload_size: int = 0
    flags: dict = field(default_factory=dict)
    service: str = ""
    suspicious: bool = False
    threat_findings: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class InspectionResult:
    packets_analyzed: int = 0
    suspicious_packets: int = 0
    protocols_seen: dict[str, int] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    c2_indicators: list[str] = field(default_factory=list)
    packet_details: list[PacketInfo] = field(default_factory=list)
    threat_score: int = 0


class PacketInspector:
    """
    Analyzes raw or simulated packet data.
    Performs protocol identification, payload scanning, and C2 beacon detection.
    """

    def inspect_raw(self, raw_data: bytes) -> InspectionResult:
        result = InspectionResult()
        packet = self._parse_ipv4(raw_data)
        if packet:
            result.packets_analyzed = 1
            self._scan_payload(raw_data, packet)
            if packet.suspicious:
                result.suspicious_packets = 1
            result.packet_details.append(packet)
            proto = packet.protocol
            result.protocols_seen[proto] = result.protocols_seen.get(proto, 0) + 1
            result.findings.extend(packet.threat_findings)
        result.threat_score = min(len(result.findings) * 15, 100)
        return result

    def inspect_stream(self, packets: list[bytes]) -> InspectionResult:
        result = InspectionResult()
        for raw in packets:
            sub = self.inspect_raw(raw)
            result.packets_analyzed += sub.packets_analyzed
            result.suspicious_packets += sub.suspicious_packets
            result.findings.extend(sub.findings)
            result.c2_indicators.extend(sub.c2_indicators)
            result.packet_details.extend(sub.packet_details)
            for proto, count in sub.protocols_seen.items():
                result.protocols_seen[proto] = result.protocols_seen.get(proto, 0) + count
        result.threat_score = min(len(result.findings) * 15, 100)
        return result

    def inspect_payload_bytes(self, payload: bytes, src: str = "", dst: str = "") -> InspectionResult:
        result = InspectionResult()
        result.packets_analyzed = 1

        findings: list[str] = []
        c2: list[str] = []

        for pattern, description in SUSPICIOUS_PAYLOAD_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                findings.append(f"Payload pattern '{description}' detected")

        for pattern in C2_BEACON_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                c2.append(f"C2 beacon pattern matched: {pattern[:40].decode('latin-1', errors='replace')!r}")

        result.findings = findings
        result.c2_indicators = c2
        if findings or c2:
            result.suspicious_packets = 1
        result.threat_score = min((len(findings) + len(c2) * 2) * 15, 100)
        return result

    def _parse_ipv4(self, data: bytes) -> Optional[PacketInfo]:
        if len(data) < 20:
            return None
        try:
            version_ihl = data[0]
            version = (version_ihl >> 4)
            if version != 4:
                return None
            ihl = (version_ihl & 0x0F) * 4
            protocol_num = data[9]
            src_ip = ".".join(str(b) for b in data[12:16])
            dst_ip = ".".join(str(b) for b in data[16:20])

            protocol = PROTOCOL_MAP.get(protocol_num, f"PROTO_{protocol_num}")
            packet = PacketInfo(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)

            if protocol == "TCP" and len(data) >= ihl + 20:
                tcp = data[ihl:ihl + 20]
                packet.src_port = struct.unpack(">H", tcp[0:2])[0]
                packet.dst_port = struct.unpack(">H", tcp[2:4])[0]
                flags_byte = tcp[13]
                packet.flags = {
                    "SYN": bool(flags_byte & 0x02),
                    "ACK": bool(flags_byte & 0x10),
                    "FIN": bool(flags_byte & 0x01),
                    "RST": bool(flags_byte & 0x04),
                    "PSH": bool(flags_byte & 0x08),
                    "URG": bool(flags_byte & 0x20),
                }
                tcp_header_len = ((tcp[12] >> 4) * 4)
                payload = data[ihl + tcp_header_len:]
                packet.payload_size = len(payload)
                if payload:
                    self._scan_payload(payload, packet)

            elif protocol == "UDP" and len(data) >= ihl + 8:
                udp = data[ihl:ihl + 8]
                packet.src_port = struct.unpack(">H", udp[0:2])[0]
                packet.dst_port = struct.unpack(">H", udp[2:4])[0]
                payload = data[ihl + 8:]
                packet.payload_size = len(payload)

            packet.service = PORT_SERVICE_MAP.get(
                packet.dst_port,
                PORT_SERVICE_MAP.get(packet.src_port, ""),
            )
            return packet
        except Exception:
            return None

    def _scan_payload(self, payload: bytes, packet: PacketInfo) -> None:
        for pattern, description in SUSPICIOUS_PAYLOAD_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                packet.suspicious = True
                packet.threat_findings.append(f"{description} in {packet.src_ip}→{packet.dst_ip}")

        for pattern in C2_BEACON_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                packet.suspicious = True
                packet.threat_findings.append(
                    f"C2 beacon pattern matched (port {packet.dst_port}) {packet.src_ip}→{packet.dst_ip}"
                )

    def generate_demo_packets(self) -> list[dict]:
        """Generate realistic demo packet records for the UI."""
        import random
        import time
        base_time = time.time()
        packets = []
        demo = [
            ("192.168.1.5", "8.8.8.8",        443, "HTTPS",    "ESTABLISHED", False, "Normal browsing"),
            ("192.168.1.5", "185.220.101.45",  6667, "IRC",     "ESTABLISHED", True,  "C2 beacon via IRC"),
            ("192.168.1.5", "198.96.155.10",   4444, "TCP",     "ESTABLISHED", True,  "Metasploit reverse shell"),
            ("192.168.1.5", "1.1.1.1",         53,  "DNS",      "UDP",         False, "DNS query"),
            ("192.168.1.5", "93.184.216.34",   80,  "HTTP",     "ESTABLISHED", False, "HTTP request"),
            ("192.168.1.5", "evil-malware.ru", 8080, "HTTP-Alt","ESTABLISHED", True,  "HTTP exfiltration"),
            ("0.0.0.0",     "",                3389, "RDP",     "LISTEN",      False, "RDP listener"),
        ]
        for i, (src, dst, port, proto, status, susp, note) in enumerate(demo):
            packets.append({
                "id": i + 1,
                "timestamp": datetime.fromtimestamp(base_time - i * 2.3).strftime("%H:%M:%S.%f")[:12],
                "src": src,
                "dst": dst,
                "port": port,
                "protocol": proto,
                "status": status,
                "suspicious": susp,
                "size": random.randint(64, 1500),
                "note": note,
            })
        return packets
