"""
CCIT File Monitor / Malware Analyzer Module
Detects spyware and ransomware indicators through static and behavioral analysis.
Checks entropy, packer signatures, suspicious strings, persistence markers, and behavior patterns.
All logic is custom-built — no clones of existing antivirus tools.
"""

import math
import os
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from modules.logger import logger
from modules.threat_scorer import ThreatScorer


SUSPICIOUS_API_STRINGS = [
    b"GetKeyState", b"SetWindowsHookEx", b"GetAsyncKeyState",
    b"ReadProcessMemory", b"WriteProcessMemory", b"VirtualAllocEx",
    b"CreateRemoteThread", b"NtCreateThreadEx", b"ZwCreateThreadEx",
    b"RegSetValueEx", b"RegCreateKeyEx", b"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    b"CryptEncrypt", b"CryptGenKey", b"BCryptEncrypt",
    b"FindFirstFile", b"FindNextFile", b"DeleteFile",
    b"InternetOpen", b"InternetConnect", b"HttpSendRequest",
    b"WSAStartup", b"connect", b"send", b"recv",
    b"shell32", b"ShellExecute", b"WinExec", b"CreateProcess",
    b"cmd.exe", b"powershell", b"wscript", b"cscript",
    b"AppData\\Roaming", b"Temp", b"System32",
    b"Login Data", b"Cookies", b"Web Data", b"key3.db", b"logins.json",
]

PACKER_SIGNATURES = {
    "UPX":    [b"UPX0", b"UPX1", b"UPX!"],
    "MPRESS": [b"MPRESS1", b"MPRESS2"],
    "Themida": [b"\x60\xE8\x00\x00\x00\x00\x5D"],
    "Enigma":  [b"EnigmaStub"],
    "ASPack":  [b"\x60\xE8\x03\x00\x00\x00\xE9\xEB"],
    "PECompact": [b"PEC2"],
    "FSG":     [b"\xEB\x04\xAF\x19\xC0\x1D"],
    "NSPack":  [b"NS_PACK"],
}

RANSOMWARE_PATTERNS = [
    rb"\.locked", rb"\.encrypted", rb"HOW_TO_DECRYPT",
    rb"YOUR_FILES_ARE_ENCRYPTED", rb"DECRYPT_INSTRUCTIONS",
    rb"tor2web", rb"\.onion", rb"bitcoin", rb"ransom",
    rb"shadow\s+copy", rb"vssadmin\s+delete",
    rb"wbadmin\s+delete\s+catalog",
    rb"bcdedit\s+/set\s+.*recoveryenabled\s+no",
]

KEYLOGGER_PATTERNS = [
    rb"GetKeyState\x00", rb"GetAsyncKeyState\x00",
    rb"SetWindowsHookEx\x00", rb"CallNextHookEx\x00",
    rb"GetClipboardData\x00", rb"OpenClipboard\x00",
    rb"WM_KEYDOWN", rb"WM_KEYUP", rb"VK_SHIFT",
]

CREDENTIAL_ACCESS_PATTERNS = [
    rb"Login Data", rb"Cookies", rb"Web Data",
    rb"key3\.db", rb"logins\.json", rb"signons\.sqlite",
    rb"DPAPI", rb"CryptUnprotectData",
    rb"SAM", rb"SYSTEM", rb"SECURITY",
    rb"lsass\.exe", rb"mimikatz",
    rb"sekurlsa", rb"privilege::debug",
]

STARTUP_PERSISTENCE_PATTERNS = [
    rb"CurrentVersion\\Run",
    rb"CurrentVersion\\RunOnce",
    rb"CurrentVersion\\Winlogon",
    rb"Userinit",
    rb"Shell\x00explorer",
    rb"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    rb"schtasks.*create",
    rb"at\s+\d{2}:\d{2}",
    rb"sc\s+create",
]

NETWORK_EXFIL_PATTERNS = [
    rb"InternetOpenUrl", rb"InternetReadFile",
    rb"HttpOpenRequest", rb"HttpSendRequest",
    rb"WSASend", rb"sendto",
    rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    rb"User-Agent:", rb"Content-Type:",
    rb"POST ", rb"GET ",
]


@dataclass
class FileAnalysisResult:
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    file_type: str = "UNKNOWN"
    sha256: str = ""
    md5: str = ""
    threat_score: int = 0
    verdict: str = "UNKNOWN"
    entropy: float = 0.0
    packer_detected: Optional[str] = None
    is_pe: bool = False
    pe_sections: list[dict] = field(default_factory=list)
    pe_imports: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    ransomware_indicators: list[str] = field(default_factory=list)
    keylogger_indicators: list[str] = field(default_factory=list)
    credential_access: list[str] = field(default_factory=list)
    persistence_mechanisms: list[str] = field(default_factory=list)
    network_indicators: list[str] = field(default_factory=list)
    behavioral_flags: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None


class FileMonitor:
    """
    Static file analysis and behavioral pattern detection.
    Identifies spyware, ransomware, keyloggers, and credential stealers.
    """

    def __init__(self) -> None:
        self.scorer = ThreatScorer()

    def analyze_file(self, file_path: str) -> FileAnalysisResult:
        result = FileAnalysisResult(file_path=file_path)
        result.file_name = os.path.basename(file_path)
        logger.info(f"Analyzing file: {file_path}", module="FILE_MONITOR")

        try:
            if not os.path.isfile(file_path):
                result.error = "File not found"
                return result

            result.file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as fh:
                data = fh.read()

            result.sha256 = self._sha256(data)
            result.md5 = self._md5(data)
            result.file_type = self._detect_file_type(data)
            result.entropy = self._calculate_entropy(data)

            if data[:2] == b"MZ":
                result.is_pe = True
                self._analyze_pe(data, result)

            self._detect_packers(data, result)
            self._scan_suspicious_strings(data, result)
            self._detect_ransomware(data, result)
            self._detect_keylogger(data, result)
            self._detect_credential_access(data, result)
            self._detect_persistence(data, result)
            self._detect_network_exfil(data, result)
            self._calculate_score(result)

        except PermissionError:
            result.error = "Permission denied — insufficient privileges to read file"
        except Exception as exc:
            result.error = str(exc)
            logger.error(f"File analysis failed: {exc}", module="FILE_MONITOR")

        return result

    def analyze_demo(self) -> FileAnalysisResult:
        """Return demo results for UI display without requiring an actual file."""
        result = FileAnalysisResult(
            file_path="/tmp/suspicious_update.exe",
            file_name="suspicious_update.exe",
            file_size=524288,
            file_type="PE32 Executable",
            sha256="a3f5c2d8e9b17640f2a1c3e5b7d9f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4",
            md5="e4d909c290d0fb1ca068ffaddf22cbd0",
            threat_score=88,
            verdict="HIGH_RISK",
            entropy=7.82,
            packer_detected="UPX",
            is_pe=True,
        )
        result.pe_sections = [
            {"name": "UPX0", "virtual_size": 0x1000, "raw_size": 0, "entropy": 0.0},
            {"name": "UPX1", "virtual_size": 0x7C000, "raw_size": 0x7B800, "entropy": 7.9},
        ]
        result.ransomware_indicators = ["File extension changer pattern", "Shadow copy deletion commands"]
        result.keylogger_indicators = ["SetWindowsHookEx (keyboard hook)", "GetAsyncKeyState"]
        result.credential_access = ["Login Data access (Chrome credentials)", "DPAPI usage detected"]
        result.persistence_mechanisms = ["HKCU\\Run registry key write", "Startup folder reference"]
        result.network_indicators = ["Outbound HTTP POST to 185.220.101.45:8080", "C2 beacon pattern"]
        result.suspicious_strings = [
            "cmd.exe /c vssadmin delete shadows /all /quiet",
            "powershell -enc JABzAD0ATgBlAHcA",
            "http://185.220.101.45/c2/beacon",
        ]
        result.behavioral_flags = [
            "High entropy (7.82) — likely packed/encrypted",
            "UPX packer detected — obfuscation attempt",
            "Ransomware string patterns (8 matches)",
            "Keylogger API calls (3 matches)",
            "Credential store access patterns (4 matches)",
            "Persistence mechanism (registry run key)",
            "Network exfiltration pattern (C2 beacon)",
        ]
        result.indicators = result.behavioral_flags
        return result

    def _sha256(self, data: bytes) -> str:
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def _md5(self, data: bytes) -> str:
        import hashlib
        return hashlib.md5(data).hexdigest()

    def _detect_file_type(self, data: bytes) -> str:
        signatures = {
            b"MZ":       "PE32 Executable",
            b"\x7fELF": "ELF Executable",
            b"\xca\xfe\xba\xbe": "Mach-O Executable",
            b"PK\x03\x04": "ZIP Archive",
            b"\x1f\x8b": "GZIP Archive",
            b"Rar!":    "RAR Archive",
            b"%PDF":    "PDF Document",
            b"\xd0\xcf\x11\xe0": "MS Office Document",
            b"PK\x03\x04\x14\x00\x06\x00": "OOXML Document",
        }
        for sig, name in signatures.items():
            if data[:len(sig)] == sig:
                return name
        return "Unknown Binary"

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _analyze_pe(self, data: bytes, result: FileAnalysisResult) -> None:
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            pe_sig = data[e_lfanew:e_lfanew + 4]
            if pe_sig != b"PE\x00\x00":
                return

            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            optional_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
            section_table_offset = e_lfanew + 24 + optional_header_size

            for i in range(min(num_sections, 16)):
                offset = section_table_offset + i * 40
                if offset + 40 > len(data):
                    break
                name = data[offset:offset + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
                virtual_size = struct.unpack_from("<I", data, offset + 16)[0]
                raw_size = struct.unpack_from("<I", data, offset + 20)[0]
                raw_offset = struct.unpack_from("<I", data, offset + 20)[0]

                section_data = data[raw_offset:raw_offset + raw_size] if raw_size else b""
                entropy = self._calculate_entropy(section_data)

                result.pe_sections.append({
                    "name": name,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "entropy": entropy,
                })

                if entropy > 7.2:
                    result.behavioral_flags.append(
                        f"High entropy section '{name}' ({entropy:.2f}) — packed or encrypted"
                    )
        except Exception:
            pass

    def _detect_packers(self, data: bytes, result: FileAnalysisResult) -> None:
        for packer, sigs in PACKER_SIGNATURES.items():
            for sig in sigs:
                if sig in data:
                    result.packer_detected = packer
                    result.behavioral_flags.append(f"Packer detected: {packer}")
                    result.indicators.append(f"Executable packer '{packer}' detected — code is obfuscated")
                    return

    def _scan_suspicious_strings(self, data: bytes, result: FileAnalysisResult) -> None:
        for pattern in SUSPICIOUS_API_STRINGS:
            if pattern in data:
                decoded = pattern.decode("latin-1", errors="replace").strip("\x00")
                if decoded not in result.suspicious_strings:
                    result.suspicious_strings.append(decoded)

        printable = re.findall(rb"[ -~]{8,}", data)
        for s in printable:
            decoded = s.decode("latin-1", errors="replace")
            if re.search(r"https?://", decoded) or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", decoded):
                if decoded not in result.suspicious_strings:
                    result.suspicious_strings.append(decoded[:200])

    def _detect_ransomware(self, data: bytes, result: FileAnalysisResult) -> None:
        for pattern in RANSOMWARE_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                decoded = pattern.decode("latin-1", errors="replace").replace(r"\s+", " ").replace(r"\.", ".")
                result.ransomware_indicators.append(f"Ransomware pattern: {decoded}")
                result.indicators.append(f"Ransomware indicator: {decoded}")

    def _detect_keylogger(self, data: bytes, result: FileAnalysisResult) -> None:
        for pattern in KEYLOGGER_PATTERNS:
            if re.search(pattern, data):
                decoded = pattern.decode("latin-1", errors="replace").strip("\x00")
                result.keylogger_indicators.append(f"Keylogger API: {decoded}")
                result.indicators.append(f"Keylogging pattern detected: {decoded}")

    def _detect_credential_access(self, data: bytes, result: FileAnalysisResult) -> None:
        for pattern in CREDENTIAL_ACCESS_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                decoded = pattern.decode("latin-1", errors="replace").replace(r"\.", ".")
                result.credential_access.append(f"Credential access: {decoded}")
                result.indicators.append(f"Browser/credential store access pattern: {decoded}")

    def _detect_persistence(self, data: bytes, result: FileAnalysisResult) -> None:
        for pattern in STARTUP_PERSISTENCE_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                decoded = pattern.decode("latin-1", errors="replace")
                result.persistence_mechanisms.append(f"Persistence: {decoded}")
                result.indicators.append(f"Persistence mechanism: {decoded}")

    def _detect_network_exfil(self, data: bytes, result: FileAnalysisResult) -> None:
        for pattern in NETWORK_EXFIL_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                decoded = pattern.decode("latin-1", errors="replace")
                result.network_indicators.append(f"Network: {decoded}")

        ip_matches = re.findall(rb"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", data)
        seen_ips = set()
        for groups in ip_matches:
            ip = ".".join(g.decode() for g in groups)
            octets = [int(g.decode()) for g in groups]
            if all(0 <= o <= 255 for o in octets) and ip not in seen_ips:
                seen_ips.add(ip)
                result.network_indicators.append(f"Embedded IP address: {ip}")
                result.indicators.append(f"Hardcoded IP address in binary: {ip}")
            if len(seen_ips) > 10:
                break

    def _calculate_score(self, result: FileAnalysisResult) -> None:
        score = 0

        if result.entropy > 7.5:
            score += 16
        elif result.entropy > 7.0:
            score += 10

        if result.packer_detected:
            score += 20

        score += min(len(result.ransomware_indicators) * 8, 24)
        score += min(len(result.keylogger_indicators) * 8, 24)
        score += min(len(result.credential_access) * 8, 24)
        score += min(len(result.persistence_mechanisms) * 8, 20)
        score += min(len(result.network_indicators) * 4, 16)
        score += min(len(result.suspicious_strings) * 1, 10)

        result.threat_score = min(score, 100)

        if result.threat_score >= 80:
            result.verdict = "HIGH_RISK"
        elif result.threat_score >= 60:
            result.verdict = "SUSPICIOUS"
        elif result.threat_score >= 30:
            result.verdict = "LOW_RISK"
        else:
            result.verdict = "CLEAN"

        result.behavioral_flags = (
            result.ransomware_indicators
            + result.keylogger_indicators
            + result.credential_access
            + result.persistence_mechanisms
        )

        logger.info(
            f"File analysis complete — score: {result.threat_score}/100 verdict: {result.verdict}",
            module="FILE_MONITOR",
        )
