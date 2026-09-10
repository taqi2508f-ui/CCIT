"""
CCIT Signature Matcher Module
Custom YARA-like pattern matching engine using Python byte patterns and regex.
Matches binary signatures, string indicators, and behavioral patterns against a built-in ruleset.
No external signature tools or databases are used — all rules are written in-house.
"""

import re
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class MatchedRule:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    matched_strings: list[str] = field(default_factory=list)
    offset: int = 0


@dataclass
class SignatureMatchResult:
    matched_rules: list[MatchedRule] = field(default_factory=list)
    total_matches: int = 0
    highest_severity: str = "NONE"
    categories_hit: list[str] = field(default_factory=list)
    threat_score_contribution: int = 0


SEVERITY_WEIGHTS = {
    "INFO": 2,
    "LOW": 5,
    "MEDIUM": 12,
    "HIGH": 22,
    "CRITICAL": 35,
}

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Rule:
    """A single detection rule with byte patterns and/or regex patterns."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        category: str,
        severity: str,
        description: str,
        byte_patterns: list[bytes] | None = None,
        regex_patterns: list[str] | None = None,
        require_all: bool = False,
        condition: Optional[Callable[[bytes], bool]] = None,
    ) -> None:
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.description = description
        self.byte_patterns = byte_patterns or []
        self.regex_patterns = [re.compile(p, re.IGNORECASE) for p in (regex_patterns or [])]
        self.require_all = require_all
        self.condition = condition

    def match(self, data: bytes) -> Optional[MatchedRule]:
        matched_strings: list[str] = []
        found_byte: list[bool] = []
        found_regex: list[bool] = []

        for bp in self.byte_patterns:
            idx = data.find(bp)
            if idx != -1:
                found_byte.append(True)
                matched_strings.append(f"bytes:{bp[:32].decode('latin-1', errors='replace')!r}@{idx}")
            else:
                found_byte.append(False)

        for pattern in self.regex_patterns:
            m = pattern.search(data)
            if m:
                found_regex.append(True)
                matched_strings.append(f"regex:{m.group()[:64].decode('latin-1', errors='replace')!r}")
            else:
                found_regex.append(False)

        all_patterns = found_byte + found_regex

        if not all_patterns:
            return None

        if self.require_all:
            triggered = all(all_patterns)
        else:
            triggered = any(all_patterns)

        if self.condition and not self.condition(data):
            triggered = False

        if not triggered:
            return None

        return MatchedRule(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
            severity=self.severity,
            description=self.description,
            matched_strings=matched_strings,
        )


BUILTIN_RULES: list[Rule] = [
    Rule(
        "SIG-001", "UPX Packer", "obfuscation", "MEDIUM",
        "File is packed with UPX — original code is hidden.",
        byte_patterns=[b"UPX0", b"UPX1", b"UPX!"],
    ),
    Rule(
        "SIG-002", "MPRESS Packer", "obfuscation", "MEDIUM",
        "File is packed with MPRESS packer.",
        byte_patterns=[b"MPRESS1", b"MPRESS2"],
    ),
    Rule(
        "SIG-003", "Keyboard Hook Install", "keylogger", "HIGH",
        "Installs a system-wide keyboard hook for keylogging.",
        byte_patterns=[b"SetWindowsHookExA", b"SetWindowsHookExW"],
    ),
    Rule(
        "SIG-004", "Async Key State Read", "keylogger", "HIGH",
        "Reads keyboard state asynchronously — common keylogger technique.",
        byte_patterns=[b"GetAsyncKeyState"],
    ),
    Rule(
        "SIG-005", "Clipboard Capture", "spyware", "MEDIUM",
        "Accesses system clipboard to capture copied data.",
        byte_patterns=[b"GetClipboardData", b"OpenClipboard"],
        require_all=True,
    ),
    Rule(
        "SIG-006", "Remote Thread Injection", "injection", "CRITICAL",
        "Creates a thread in another process — process injection technique.",
        byte_patterns=[b"CreateRemoteThread"],
    ),
    Rule(
        "SIG-007", "NtCreateThreadEx Injection", "injection", "CRITICAL",
        "Uses low-level NtCreateThreadEx for stealth process injection.",
        byte_patterns=[b"NtCreateThreadEx", b"ZwCreateThreadEx"],
    ),
    Rule(
        "SIG-008", "Process Memory Write", "injection", "HIGH",
        "Writes into another process's memory — characteristic of code injection.",
        byte_patterns=[b"WriteProcessMemory"],
    ),
    Rule(
        "SIG-009", "Registry Persistence (Run Key)", "persistence", "HIGH",
        "Writes to auto-run registry key for startup persistence.",
        regex_patterns=[rb"CurrentVersion\\Run(?:Once)?"],
    ),
    Rule(
        "SIG-010", "Winlogon Registry Persistence", "persistence", "CRITICAL",
        "Modifies Winlogon registry key for deep persistence.",
        regex_patterns=[rb"CurrentVersion\\Winlogon"],
    ),
    Rule(
        "SIG-011", "Mass File Encryption Pattern", "ransomware", "CRITICAL",
        "Cryptographic API calls combined with file enumeration — ransomware pattern.",
        byte_patterns=[b"CryptEncrypt", b"FindFirstFileW"],
        require_all=True,
    ),
    Rule(
        "SIG-012", "Shadow Copy Deletion", "ransomware", "CRITICAL",
        "Deletes Volume Shadow Copies to prevent data recovery.",
        regex_patterns=[rb"vssadmin\s+delete\s+shadows", rb"wbadmin\s+delete\s+catalog"],
    ),
    Rule(
        "SIG-013", "BCrypt File Encryption", "ransomware", "HIGH",
        "Uses modern BCrypt API for file encryption — ransomware indicator.",
        byte_patterns=[b"BCryptEncrypt", b"BCryptGenKey"],
        require_all=True,
    ),
    Rule(
        "SIG-014", "Chrome Credential Theft", "credential_theft", "CRITICAL",
        "Accesses Chrome's Login Data file — steals saved passwords.",
        byte_patterns=[b"Login Data"],
    ),
    Rule(
        "SIG-015", "Firefox Credential Theft", "credential_theft", "CRITICAL",
        "Accesses Firefox credential database.",
        byte_patterns=[b"logins.json", b"key3.db", b"key4.db"],
    ),
    Rule(
        "SIG-016", "DPAPI Credential Decryption", "credential_theft", "HIGH",
        "Uses Windows DPAPI to decrypt stored credentials.",
        byte_patterns=[b"CryptUnprotectData"],
    ),
    Rule(
        "SIG-017", "LSASS Memory Read", "credential_theft", "CRITICAL",
        "Reads LSASS process memory — password hash dumping technique.",
        byte_patterns=[b"lsass.exe"],
        regex_patterns=[rb"(?i)sekurlsa|mimikatz|privilege::debug"],
    ),
    Rule(
        "SIG-018", "PowerShell Encoded Command", "execution", "HIGH",
        "Executes base64-encoded PowerShell command — obfuscation technique.",
        regex_patterns=[rb"powershell.*-e(?:nc|ncode(?:dcommand)?)\s+[A-Za-z0-9+/=]{20,}"],
    ),
    Rule(
        "SIG-019", "Shell Command Execution", "execution", "MEDIUM",
        "Spawns a command shell process.",
        byte_patterns=[b"cmd.exe /c", b"cmd /c "],
    ),
    Rule(
        "SIG-020", "WScript/CScript Execution", "execution", "MEDIUM",
        "Executes Windows Script Host — often used to run malicious VBScript/JScript.",
        byte_patterns=[b"wscript.exe", b"cscript.exe"],
    ),
    Rule(
        "SIG-021", "Reverse Shell Pattern", "backdoor", "CRITICAL",
        "Network connection pattern characteristic of reverse shell.",
        regex_patterns=[
            rb"socket\(\s*AF_INET.*SOCK_STREAM.*connect\(",
            rb"nc\s+-[elv]+\s+\d{1,3}\.\d{1,3}",
        ],
    ),
    Rule(
        "SIG-022", "Tor Onion Address", "c2", "HIGH",
        "References a .onion address — Tor-based C2 or payment.",
        regex_patterns=[rb"[a-z2-7]{16,56}\.onion"],
    ),
    Rule(
        "SIG-023", "Bitcoin Ransom Address", "ransomware", "HIGH",
        "Contains Bitcoin or Monero payment address.",
        regex_patterns=[rb"(?:1|3|bc1)[A-HJ-NP-Za-km-z1-9]{25,39}", rb"bitcoin|monero|ethereum"],
    ),
    Rule(
        "SIG-024", "Anti-VM Detection", "evasion", "MEDIUM",
        "Checks for virtual machine artifacts — evasion technique.",
        byte_patterns=[b"VBOX", b"VMWARE", b"VirtualBox"],
        regex_patterns=[rb"VBox|VMware|QEMU|bochs|xen"],
    ),
    Rule(
        "SIG-025", "Anti-Debug Detection", "evasion", "MEDIUM",
        "Checks if a debugger is attached — analysis evasion.",
        byte_patterns=[b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"],
    ),
    Rule(
        "SIG-026", "Browser Credential Store Access", "credential_theft", "HIGH",
        "Accesses multiple browser credential locations.",
        regex_patterns=[rb"(?:Login\s+Data|Web\s+Data|Cookies|logins\.json)", ],
    ),
    Rule(
        "SIG-027", "Startup Folder Persistence", "persistence", "HIGH",
        "Drops file into Windows startup folder.",
        regex_patterns=[rb"(?i)Start\s+Menu\\Programs\\Startup"],
    ),
    Rule(
        "SIG-028", "Scheduled Task Creation", "persistence", "HIGH",
        "Creates a scheduled task for persistent execution.",
        regex_patterns=[rb"schtasks.*(?:/create|/tn)", rb"Task\s+Scheduler"],
    ),
    Rule(
        "SIG-029", "HTTP C2 Beacon Pattern", "c2", "HIGH",
        "HTTP communication pattern consistent with C2 beacon.",
        regex_patterns=[
            rb"(?:GET|POST)\s+/(?:beacon|check(?:in)?|update|report|ping|gate)\s+HTTP/",
            rb"User-Agent:\s*[A-Za-z0-9]{5,20}$",
        ],
    ),
    Rule(
        "SIG-030", "DNS C2 Exfiltration Pattern", "c2", "HIGH",
        "Data encoded in DNS subdomains — DNS tunneling/exfiltration.",
        regex_patterns=[rb"[A-Za-z0-9]{32,}\.(?:[a-z]{2,10}\.){2,}[a-z]{2,6}"],
    ),
]


class SignatureMatcher:
    """
    Custom signature matching engine.
    Scans binary data against the built-in ruleset and returns all matches.
    """

    def __init__(self) -> None:
        self._rules = BUILTIN_RULES

    def scan(self, data: bytes) -> SignatureMatchResult:
        matched: list[MatchedRule] = []
        for rule in self._rules:
            match = rule.match(data)
            if match:
                matched.append(match)

        result = SignatureMatchResult(
            matched_rules=matched,
            total_matches=len(matched),
        )

        if matched:
            categories = list({r.category for r in matched})
            result.categories_hit = categories

            severities = [r.severity for r in matched]
            highest = max(severities, key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0)
            result.highest_severity = highest

            score = sum(SEVERITY_WEIGHTS.get(r.severity, 0) for r in matched)
            result.threat_score_contribution = min(score, 100)

        return result

    def scan_text(self, text: str) -> SignatureMatchResult:
        return self.scan(text.encode("utf-8", errors="replace"))

    def add_custom_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def list_rules(self) -> list[dict]:
        return [
            {
                "id": r.rule_id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity,
                "description": r.description,
            }
            for r in self._rules
        ]

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        for r in self._rules:
            if r.rule_id == rule_id:
                return r
        return None
