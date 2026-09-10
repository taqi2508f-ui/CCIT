"""
CCIT Threat Scorer Module
Central scoring engine that normalizes threat signals from all analyzers into
a consistent 0–100 risk score with severity labels and recommendation text.
"""

from dataclasses import dataclass, field
from typing import Optional


SEVERITY_LABELS = {
    (0,   0):  ("CLEAN",    "#00FF41", "No threats detected."),
    (1,  29):  ("LOW",      "#AAFF00", "Minor anomalies — monitor but not immediately dangerous."),
    (30, 59):  ("MEDIUM",   "#FFAA00", "Suspicious indicators — investigate before trusting."),
    (60, 79):  ("HIGH",     "#FF6600", "High-confidence threat — take defensive action now."),
    (80, 94):  ("CRITICAL", "#FF0055", "Critical threat — block and isolate immediately."),
    (95, 100): ("EXTREME",  "#FF00FF", "Extreme threat — confirmed malicious activity."),
}


@dataclass
class ThreatSignal:
    """A single piece of evidence contributing to a threat score."""

    name: str
    weight: int
    description: str
    category: str = "generic"
    matched: bool = False
    evidence: Optional[str] = None


@dataclass
class ThreatScore:
    raw_score: int = 0
    normalized: int = 0
    severity: str = "CLEAN"
    color: str = "#00FF41"
    recommendation: str = ""
    signals: list[ThreatSignal] = field(default_factory=list)
    breakdown: dict[str, int] = field(default_factory=dict)

    @property
    def as_percentage(self) -> float:
        return round(self.normalized / 100, 2)


class ThreatScorer:
    """
    Aggregates evidence signals and produces a normalized threat score.
    All scoring rules are custom-defined — no external threat intel APIs required.
    """

    SIGNAL_CATALOG: list[dict] = [
        {"name": "suspicious_tld",       "weight": 12, "category": "domain",   "description": "Suspicious or disposable TLD"},
        {"name": "ip_in_url",            "weight": 18, "category": "domain",   "description": "Bare IP address used instead of domain"},
        {"name": "brand_impersonation",  "weight": 22, "category": "domain",   "description": "Known brand name embedded in unrelated domain"},
        {"name": "homograph_attack",     "weight": 28, "category": "domain",   "description": "Unicode lookalike characters in domain"},
        {"name": "excessive_subdomains", "weight": 8,  "category": "domain",   "description": "Unusually deep subdomain chain"},
        {"name": "long_url",             "weight": 5,  "category": "domain",   "description": "Excessively long URL (obfuscation)"},
        {"name": "phishing_keywords",    "weight": 10, "category": "content",  "description": "Phishing-related keywords in path or query"},
        {"name": "no_https",             "weight": 14, "category": "ssl",      "description": "No SSL/TLS encryption"},
        {"name": "ssl_mismatch",         "weight": 18, "category": "ssl",      "description": "SSL certificate hostname mismatch"},
        {"name": "invalid_ssl",          "weight": 20, "category": "ssl",      "description": "Invalid or self-signed SSL certificate"},
        {"name": "free_ssl",             "weight": 4,  "category": "ssl",      "description": "Free/automated certificate (Let's Encrypt)"},
        {"name": "redirect_chain",       "weight": 8,  "category": "network",  "description": "URL redirects through multiple hops"},
        {"name": "external_form_action", "weight": 28, "category": "content",  "description": "HTML form submits to external server"},
        {"name": "hidden_credential_form","weight": 22,"category": "content",  "description": "Hidden form capturing credentials"},
        {"name": "malicious_script",     "weight": 18, "category": "content",  "description": "Obfuscated or credential-stealing JS"},
        {"name": "ui_cloning",           "weight": 22, "category": "content",  "description": "Page loads assets from a known-brand site"},
        {"name": "tracking_pixel",       "weight": 5,  "category": "content",  "description": "1x1 tracking image present"},
        {"name": "iframe_injection",     "weight": 14, "category": "content",  "description": "Hidden iframe loading external content"},
        {"name": "dns_fail",             "weight": 18, "category": "network",  "description": "Domain does not resolve"},
        {"name": "private_ip",           "weight": 16, "category": "network",  "description": "Domain resolves to private/internal IP"},
        {"name": "suspicious_port",      "weight": 10, "category": "network",  "description": "Service running on non-standard port"},
        {"name": "spf_fail",             "weight": 18, "category": "email",    "description": "SPF record check failed"},
        {"name": "dkim_fail",            "weight": 16, "category": "email",    "description": "DKIM signature verification failed"},
        {"name": "dmarc_fail",           "weight": 14, "category": "email",    "description": "DMARC policy not met"},
        {"name": "from_display_mismatch","weight": 20, "category": "email",    "description": "Display name doesn't match envelope From"},
        {"name": "reply_to_mismatch",    "weight": 15, "category": "email",    "description": "Reply-To domain differs from sender domain"},
        {"name": "malicious_attachment", "weight": 30, "category": "email",    "description": "Dangerous file attachment detected"},
        {"name": "malicious_link",       "weight": 22, "category": "email",    "description": "URLs in email body point to phishing sites"},
        {"name": "high_entropy",         "weight": 16, "category": "file",     "description": "High entropy file content (packing/encryption)"},
        {"name": "packer_detected",      "weight": 20, "category": "file",     "description": "Executable packer signature detected"},
        {"name": "keylogger_pattern",    "weight": 28, "category": "behavior", "description": "Keylogger-like behavior detected"},
        {"name": "persistence_attempt",  "weight": 24, "category": "behavior", "description": "Startup/registry persistence attempt"},
        {"name": "encryption_activity",  "weight": 26, "category": "behavior", "description": "Mass file encryption (ransomware pattern)"},
        {"name": "credential_access",    "weight": 26, "category": "behavior", "description": "Accessing browser credential stores"},
        {"name": "exfiltration",         "weight": 28, "category": "network",  "description": "Data being sent to external server"},
        {"name": "c2_beacon",            "weight": 30, "category": "network",  "description": "Command & control beacon pattern detected"},
        {"name": "suspicious_process",   "weight": 14, "category": "process",  "description": "Suspicious child process spawned"},
        {"name": "process_injection",    "weight": 28, "category": "process",  "description": "Process injection technique detected"},
    ]

    def __init__(self) -> None:
        self._catalog = {s["name"]: s for s in self.SIGNAL_CATALOG}

    def score(self, signals: list[str], evidence: dict[str, str] | None = None) -> ThreatScore:
        """
        Compute a ThreatScore from a list of signal names.

        Args:
            signals:  List of signal names (from SIGNAL_CATALOG) that matched.
            evidence: Optional map of signal_name → evidence string for reporting.
        """
        evidence = evidence or {}
        matched: list[ThreatSignal] = []
        breakdown: dict[str, int] = {}
        raw = 0

        for sig_name in signals:
            catalog_entry = self._catalog.get(sig_name)
            if catalog_entry is None:
                continue
            ts = ThreatSignal(
                name=sig_name,
                weight=catalog_entry["weight"],
                description=catalog_entry["description"],
                category=catalog_entry["category"],
                matched=True,
                evidence=evidence.get(sig_name),
            )
            matched.append(ts)
            cat = catalog_entry["category"]
            breakdown[cat] = breakdown.get(cat, 0) + catalog_entry["weight"]
            raw += catalog_entry["weight"]

        normalized = min(int((raw / max(raw, 1)) * 100) if raw else 0, 100)
        normalized = min(raw, 100)

        severity, color, recommendation = self._get_severity(normalized)

        return ThreatScore(
            raw_score=raw,
            normalized=normalized,
            severity=severity,
            color=color,
            recommendation=recommendation,
            signals=matched,
            breakdown=breakdown,
        )

    def score_from_indicators(self, indicators: list[str]) -> ThreatScore:
        """
        Derive a score from free-text indicator strings by keyword matching.
        Useful for analyzers that produce text descriptions rather than signal names.
        """
        KEYWORD_MAP = {
            "suspicious tld": "suspicious_tld",
            "bare ip": "ip_in_url",
            "brand impersonation": "brand_impersonation",
            "homograph": "homograph_attack",
            "subdomain": "excessive_subdomains",
            "long url": "long_url",
            "phishing keyword": "phishing_keywords",
            "no https": "no_https",
            "plain http": "no_https",
            "ssl certificate cn mismatch": "ssl_mismatch",
            "invalid ssl": "invalid_ssl",
            "free/automated ssl": "free_ssl",
            "redirect": "redirect_chain",
            "external": "external_form_action",
            "credential harvesting": "hidden_credential_form",
            "malicious script": "malicious_script",
            "ui clon": "ui_cloning",
            "tracking pixel": "tracking_pixel",
            "iframe": "iframe_injection",
            "dns resolution failed": "dns_fail",
            "private/internal ip": "private_ip",
            "non-standard port": "suspicious_port",
            "spf": "spf_fail",
            "dkim": "dkim_fail",
            "dmarc": "dmarc_fail",
            "display name": "from_display_mismatch",
            "reply-to": "reply_to_mismatch",
            "attachment": "malicious_attachment",
            "malicious link": "malicious_link",
            "entropy": "high_entropy",
            "packer": "packer_detected",
            "keylog": "keylogger_pattern",
            "persistence": "persistence_attempt",
            "encrypt": "encryption_activity",
            "credential access": "credential_access",
            "exfiltration": "exfiltration",
            "c2": "c2_beacon",
            "suspicious process": "suspicious_process",
            "injection": "process_injection",
        }

        matched_signals: list[str] = []
        for indicator in indicators:
            indicator_lower = indicator.lower()
            for keyword, signal in KEYWORD_MAP.items():
                if keyword in indicator_lower and signal not in matched_signals:
                    matched_signals.append(signal)

        return self.score(matched_signals)

    def _get_severity(self, score: int) -> tuple[str, str, str]:
        for (lo, hi), (label, color, rec) in SEVERITY_LABELS.items():
            if lo <= score <= hi:
                return label, color, rec
        return "EXTREME", "#FF00FF", "Extreme threat detected."

    def get_all_signal_names(self) -> list[str]:
        return list(self._catalog.keys())

    def get_signal_info(self, name: str) -> dict | None:
        return self._catalog.get(name)
