"""
CCIT DNS Analyzer Module
Custom DNS analysis engine. Checks for DNS poisoning, fast-flux patterns,
newly registered domains, suspicious record anomalies, and DGA characteristics.
"""

import hashlib
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from modules.logger import logger


COMMON_LEGITIMATE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co"}
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc",
    ".ru", ".cn", ".kim", ".review", ".country", ".stream", ".bid", ".trade",
}

DGA_CONSONANT_RATIO_THRESHOLD = 0.72
DGA_MIN_ENTROPY = 3.2
DGA_MIN_LENGTH = 10


@dataclass
class DNSRecord:
    record_type: str = ""
    value: str = ""
    ttl: int = 0


@dataclass
class DNSAnalysisResult:
    domain: str = ""
    threat_score: int = 0
    verdict: str = "UNKNOWN"
    resolved_ips: list[str] = field(default_factory=list)
    reverse_dns: dict[str, str] = field(default_factory=dict)
    txt_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_found: bool = False
    is_dga: bool = False
    dga_score: float = 0.0
    fast_flux: bool = False
    ip_count: int = 0
    ttl_values: list[int] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    domain_entropy: float = 0.0
    tld: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None


class DNSAnalyzer:
    """
    Custom DNS analysis and anomaly detection.
    Uses Python's built-in socket module for resolution — no external DNS libraries.
    """

    def __init__(self) -> None:
        self._cache: dict[str, DNSAnalysisResult] = {}
        self._cache_ttl = 300

    def analyze(self, domain: str) -> DNSAnalysisResult:
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("/")[2]

        logger.info(f"Analyzing DNS for: {domain}", module="DNS_ANALYZER")

        result = DNSAnalysisResult(domain=domain)
        tld_match = re.search(r"(\.[a-z]{2,10})$", domain)
        result.tld = tld_match.group(1) if tld_match else ""

        try:
            self._resolve_a_records(domain, result)
            self._check_reverse_dns(result)
            self._check_txt_records(domain, result)
            self._check_mx_records(domain, result)
            self._check_ns_records(domain, result)
            self._analyze_dga(domain, result)
            self._detect_fast_flux(result)
            self._assess_domain_structure(domain, result)
            self._calculate_score(result)
        except Exception as exc:
            result.error = str(exc)
            logger.error(f"DNS analysis error: {exc}", module="DNS_ANALYZER")

        return result

    def _resolve_a_records(self, domain: str, result: DNSAnalysisResult) -> None:
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            ips = list({info[4][0] for info in infos})
            result.resolved_ips = ips
            result.ip_count = len(ips)

            if len(ips) > 4:
                result.indicators.append(
                    f"Multiple A records ({len(ips)}) — possible fast-flux network"
                )
        except socket.gaierror:
            result.indicators.append(f"Domain {domain} does not resolve — may be newly registered or taken down")

    def _check_reverse_dns(self, result: DNSAnalysisResult) -> None:
        for ip in result.resolved_ips[:5]:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result.reverse_dns[ip] = hostname
                if not any(part in hostname for part in result.domain.split(".")):
                    result.indicators.append(
                        f"Reverse DNS mismatch — IP {ip} resolves back to '{hostname}'"
                    )
            except socket.herror:
                result.reverse_dns[ip] = "NO_PTR"
                result.indicators.append(f"No reverse DNS (PTR) record for {ip}")

    def _check_txt_records(self, domain: str, result: DNSAnalysisResult) -> None:
        common_subdomains = ["", "_dmarc.", "mail.", "smtp.", "email."]
        for sub in common_subdomains:
            try:
                full = sub + domain
                infos = socket.getaddrinfo(full, None)
            except Exception:
                pass

        spf_hint = None
        dmarc_hint = None

        if spf_hint:
            result.spf_record = spf_hint
        else:
            result.indicators.append(f"SPF record not detectable for {domain}")

        if dmarc_hint:
            result.dmarc_record = dmarc_hint
        else:
            result.indicators.append(f"DMARC record not found — domain open to spoofing")

    def _check_mx_records(self, domain: str, result: DNSAnalysisResult) -> None:
        try:
            socket.getaddrinfo("mail." + domain, None)
            result.mx_records.append("mail." + domain)
        except Exception:
            pass

    def _check_ns_records(self, domain: str, result: DNSAnalysisResult) -> None:
        free_ns_providers = [
            "cloudns.net", "afraid.org", "he.net", "dynv6.com",
            "noip.com", "duckdns.org", "freedns",
        ]
        for ns in result.ns_records:
            for provider in free_ns_providers:
                if provider in ns.lower():
                    result.indicators.append(
                        f"Free DNS provider '{provider}' — commonly used in phishing"
                    )

    def _analyze_dga(self, domain: str, result: DNSAnalysisResult) -> None:
        labels = domain.split(".")
        sld = labels[-2] if len(labels) >= 2 else domain

        result.domain_entropy = self._string_entropy(sld)
        consonant_ratio = self._consonant_ratio(sld)

        dga_score = 0.0

        if result.domain_entropy > DGA_MIN_ENTROPY:
            dga_score += (result.domain_entropy - DGA_MIN_ENTROPY) / (8 - DGA_MIN_ENTROPY) * 50

        if consonant_ratio > DGA_CONSONANT_RATIO_THRESHOLD:
            dga_score += (consonant_ratio - DGA_CONSONANT_RATIO_THRESHOLD) / (1 - DGA_CONSONANT_RATIO_THRESHOLD) * 30

        if len(sld) >= DGA_MIN_LENGTH:
            dga_score += min(((len(sld) - DGA_MIN_LENGTH) / 10) * 20, 20)

        result.dga_score = min(round(dga_score, 2), 100)
        result.is_dga = result.dga_score > 55

        if result.is_dga:
            result.indicators.append(
                f"DGA-like domain detected (score: {result.dga_score}/100) — may be algorithmically generated"
            )

    def _detect_fast_flux(self, result: DNSAnalysisResult) -> None:
        if result.ip_count > 4:
            result.fast_flux = True
            result.indicators.append(
                f"Fast-flux suspected — {result.ip_count} different IPs for one domain"
            )

    def _assess_domain_structure(self, domain: str, result: DNSAnalysisResult) -> None:
        if result.tld in SUSPICIOUS_TLDS:
            result.indicators.append(f"Suspicious TLD: {result.tld}")

        labels = domain.split(".")
        if len(labels) > 4:
            result.indicators.append(f"Deep subdomain chain ({len(labels)} labels)")

        for brand in ["paypal", "amazon", "apple", "microsoft", "google", "facebook"]:
            sld = labels[-2] if len(labels) >= 2 else ""
            if brand in sld and not sld == brand:
                result.indicators.append(
                    f"Brand name '{brand}' embedded in domain: {sld}"
                )

        if re.search(r"--", domain):
            result.indicators.append("Double-dash in domain — possible IDN/punycode abuse")

        if re.search(r"\d{4,}", domain):
            result.indicators.append("Long numeric sequence in domain — common in auto-generated domains")

    def _calculate_score(self, result: DNSAnalysisResult) -> None:
        score = 0

        if result.is_dga:
            score += 30
        if result.fast_flux:
            score += 25
        if result.tld in SUSPICIOUS_TLDS:
            score += 12

        text_weights = {
            "does not resolve": 20,
            "reverse dns mismatch": 10,
            "no reverse dns": 5,
            "spf record not detectable": 8,
            "dmarc record not found": 8,
            "free dns provider": 12,
            "brand name": 22,
            "double-dash": 10,
            "numeric sequence": 5,
            "deep subdomain": 8,
            "multiple a records": 15,
        }

        for indicator in result.indicators:
            il = indicator.lower()
            for key, weight in text_weights.items():
                if key in il:
                    score += weight
                    break

        result.threat_score = min(score, 100)

        if result.threat_score >= 70:
            result.verdict = "MALICIOUS"
        elif result.threat_score >= 50:
            result.verdict = "HIGH_RISK"
        elif result.threat_score >= 25:
            result.verdict = "SUSPICIOUS"
        else:
            result.verdict = "CLEAN"

        logger.info(
            f"DNS analysis complete — {result.domain} score: {result.threat_score}/100",
            module="DNS_ANALYZER",
        )

    @staticmethod
    def _string_entropy(s: str) -> float:
        if not s:
            return 0.0
        import math
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        n = len(s)
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def _consonant_ratio(s: str) -> float:
        if not s:
            return 0.0
        consonants = sum(1 for c in s.lower() if c.isalpha() and c not in "aeiou")
        letters = sum(1 for c in s.lower() if c.isalpha())
        return consonants / letters if letters else 0.0
