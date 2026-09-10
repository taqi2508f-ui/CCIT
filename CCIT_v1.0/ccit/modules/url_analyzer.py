"""
CCIT URL Analyzer Module
Custom phishing website detection engine.
Analyzes URLs for suspicious patterns, fake HTTPS, redirects, hidden forms, and data exfiltration endpoints.
No external cybersecurity tools are used — all logic is built in-house.
"""

import hashlib
import ipaddress
import re
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from modules.logger import logger
from modules.threat_scorer import ThreatScorer


SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw",
    ".cc", ".ru", ".cn", ".kim", ".review", ".country", ".stream",
}

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bank", "ebay", "instagram", "twitter", "wellsfargo",
    "chase", "citibank", "irs", "gov",
]

PHISHING_KEYWORDS = [
    "login", "signin", "account", "verify", "secure", "update",
    "confirm", "billing", "payment", "suspend", "urgent", "alert",
    "password", "credential", "authenticate", "validation",
]

MALICIOUS_SCRIPT_PATTERNS = [
    r"eval\s*\(",
    r"document\.cookie",
    r"window\.location\s*=",
    r"XMLHttpRequest",
    r"fetch\s*\(",
    r"navigator\.sendBeacon",
    r"localStorage\s*\.",
    r"sessionStorage\s*\.",
    r"atob\s*\(",
    r"String\.fromCharCode",
    r"unescape\s*\(",
]

SUSPICIOUS_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 8080, 8888, 9000}


@dataclass
class URLAnalysisResult:
    url: str
    final_url: str = ""
    threat_score: int = 0
    verdict: str = "UNKNOWN"
    redirects: list[str] = field(default_factory=list)
    ssl_info: dict = field(default_factory=dict)
    form_actions: list[dict] = field(default_factory=list)
    suspicious_scripts: list[dict] = field(default_factory=list)
    exfiltration_endpoints: list[dict] = field(default_factory=list)
    dns_info: dict = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    ip_geolocation: dict = field(default_factory=dict)
    html_fingerprint: str = ""
    page_title: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None


class URLAnalyzer:
    """
    Comprehensive URL/phishing website analyzer.
    All detection logic is custom-built — no clones of existing tools.
    """

    def __init__(self) -> None:
        self.scorer = ThreatScorer()
        self.timeout = 10

    def analyze(self, url: str) -> URLAnalysisResult:
        result = URLAnalysisResult(url=url)
        logger.info(f"Analyzing URL: {url}", module="URL_ANALYZER")

        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            result.url = url

        try:
            self._analyze_url_structure(url, result)
            self._resolve_dns(url, result)
            self._check_ssl(url, result)
            self._fetch_and_analyze_page(url, result)
            self._calculate_threat_score(result)
        except Exception as exc:
            result.error = str(exc)
            logger.error(f"URL analysis failed: {exc}", module="URL_ANALYZER")

        return result

    def _analyze_url_structure(self, url: str, result: URLAnalysisResult) -> None:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_lower = url.lower()

        indicators: list[str] = []

        tld = "." + hostname.split(".")[-1] if "." in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            indicators.append(f"Suspicious TLD: {tld}")

        try:
            ipaddress.ip_address(hostname)
            indicators.append(f"URL uses bare IP address: {hostname}")
        except ValueError:
            pass

        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 4:
            indicators.append(f"Excessive subdomains ({len(subdomain_parts)-2}): {hostname}")

        for brand in KNOWN_BRANDS:
            if brand in hostname and not hostname.endswith(f"{brand}.com"):
                indicators.append(f"Brand impersonation attempt — '{brand}' in hostname: {hostname}")

        homograph_pattern = re.compile(r"[^\x00-\x7F]")
        if homograph_pattern.search(hostname):
            indicators.append("Homograph/IDN spoofing detected in hostname")

        double_at = url.count("@")
        if double_at > 0:
            indicators.append("@ symbol in URL — possible credential embedding")

        if len(url) > 150:
            indicators.append(f"Excessively long URL ({len(url)} chars)")

        keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in path or kw in query]
        if keyword_hits:
            indicators.append(f"Phishing keywords in path/query: {', '.join(keyword_hits)}")

        dash_count = hostname.count("-")
        if dash_count >= 3:
            indicators.append(f"Excessive hyphens in domain ({dash_count}): {hostname}")

        if parsed.port and parsed.port in SUSPICIOUS_PORTS:
            indicators.append(f"Non-standard port: {parsed.port}")

        result.indicators.extend(indicators)

    def _resolve_dns(self, url: str, result: URLAnalysisResult) -> None:
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
            if not hostname:
                return

            ip = socket.gethostbyname(hostname)
            result.dns_info = {
                "hostname": hostname,
                "resolved_ip": ip,
                "resolution_successful": True,
            }

            try:
                private = ipaddress.ip_address(ip).is_private
                if private:
                    result.indicators.append(f"Domain resolves to private/internal IP: {ip}")
            except ValueError:
                pass

            result.ip_geolocation = self._geolocate_ip(ip)
        except socket.gaierror as exc:
            result.dns_info = {"resolution_successful": False, "error": str(exc)}
            result.indicators.append("DNS resolution failed — domain may not exist or be taken down")

    def _geolocate_ip(self, ip: str) -> dict:
        """
        Lightweight geolocation via IP range heuristics.
        Returns a best-effort location dict without external API calls.
        """
        geo: dict[str, str] = {"ip": ip, "method": "heuristic"}
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                geo["country"] = "LOCAL"
                geo["region"] = "Private Network"
                return geo

            octets = [int(o) for o in ip.split(".")]
            first = octets[0]
            second = octets[1] if len(octets) > 1 else 0

            if 1 <= first <= 5:
                geo.update({"country": "US", "region": "ARIN"})
            elif first in range(176, 192):
                geo.update({"country": "RU", "region": "RIPE"})
            elif first in range(58, 62):
                geo.update({"country": "CN", "region": "APNIC"})
            elif first in range(41, 44):
                geo.update({"country": "ZA", "region": "AFRINIC"})
            elif first in range(193, 200):
                geo.update({"country": "DE", "region": "RIPE"})
            else:
                geo.update({"country": "Unknown", "region": "Unknown"})
        except Exception:
            geo["error"] = "Geolocation unavailable"
        return geo

    def _check_ssl(self, url: str, result: URLAnalysisResult) -> None:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""

        if url.startswith("http://"):
            result.ssl_info = {"has_ssl": False}
            result.indicators.append("No HTTPS — plain HTTP connection (unencrypted)")
            return

        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.create_connection((hostname, 443), timeout=self.timeout),
                server_hostname=hostname,
            )
            cert = conn.getpeercert()
            conn.close()

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")
            san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

            result.ssl_info = {
                "has_ssl": True,
                "valid": True,
                "subject_cn": subject.get("commonName", ""),
                "issuer_org": issuer.get("organizationName", ""),
                "not_after": not_after,
                "san": san,
            }

            cn = subject.get("commonName", "")
            if hostname not in cn and not any(hostname.endswith(s.lstrip("*")) for s in san):
                result.indicators.append(f"SSL certificate CN mismatch — cert CN: {cn}, host: {hostname}")

            free_issuers = {"Let's Encrypt", "ZeroSSL", "cPanel", "Comodo"}
            if any(fi in issuer.get("organizationName", "") for fi in free_issuers):
                result.indicators.append("Free/automated SSL certificate (common in phishing sites)")

        except ssl.SSLError as exc:
            result.ssl_info = {"has_ssl": True, "valid": False, "error": str(exc)}
            result.indicators.append(f"Invalid SSL certificate: {exc}")
        except Exception as exc:
            result.ssl_info = {"has_ssl": True, "valid": False, "error": str(exc)}

    def _fetch_and_analyze_page(self, url: str, result: URLAnalysisResult) -> None:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                },
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                result.final_url = resp.url
                if resp.url != url:
                    result.redirects.append(resp.url)
                    result.indicators.append(f"Redirect detected: {url} → {resp.url}")

                raw = resp.read(500_000)
                html = raw.decode("utf-8", errors="replace")

            result.html_fingerprint = hashlib.sha256(html.encode()).hexdigest()[:16]

            title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            result.page_title = (title_match.group(1).strip()[:200] if title_match else "")

            self._extract_forms(html, url, result)
            self._detect_malicious_scripts(html, result)
            self._detect_ui_cloning(html, result)
            self._detect_tracking_pixels(html, result)

        except urllib.error.HTTPError as exc:
            result.error = f"HTTP {exc.code}: {exc.reason}"
            result.indicators.append(f"HTTP error {exc.code} — server returned error response")
        except Exception as exc:
            result.error = str(exc)

    def _extract_forms(self, html: str, base_url: str, result: URLAnalysisResult) -> None:
        form_pattern = re.compile(
            r"<form[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL
        )
        action_pattern = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]+type\s*=\s*["\']?password["\']?', re.IGNORECASE)

        parsed_base = urllib.parse.urlparse(base_url)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            action_match = action_pattern.search(form_html)
            has_password = bool(input_pattern.search(form_html))

            action = action_match.group(1) if action_match else ""
            if action and not action.startswith("http"):
                action = urllib.parse.urljoin(base_url, action)

            form_info: dict = {
                "has_password_field": has_password,
                "action": action,
                "suspicious": False,
                "reason": [],
            }

            if action:
                action_parsed = urllib.parse.urlparse(action)
                if action_parsed.netloc and action_parsed.netloc != parsed_base.netloc:
                    form_info["suspicious"] = True
                    form_info["reason"].append(f"Form submits to external domain: {action_parsed.netloc}")
                    result.exfiltration_endpoints.append({
                        "type": "form_action",
                        "destination": action,
                        "host": action_parsed.netloc,
                    })
                    result.indicators.append(
                        f"Form submitting credentials to EXTERNAL server: {action_parsed.netloc}"
                    )

            if has_password and not action:
                form_info["suspicious"] = True
                form_info["reason"].append("Password form with no action — may use JS to intercept")
                result.indicators.append("Hidden credential harvesting form detected")

            result.form_actions.append(form_info)

    def _detect_malicious_scripts(self, html: str, result: URLAnalysisResult) -> None:
        script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL)

        for script in script_blocks:
            hits = []
            for pattern in MALICIOUS_SCRIPT_PATTERNS:
                if re.search(pattern, script):
                    hits.append(pattern.replace(r"\s*", " ").replace(r"\.", "."))

            if hits:
                snippet = script.strip()[:120].replace("\n", " ")
                result.suspicious_scripts.append({"patterns": hits, "snippet": snippet})
                result.indicators.append(f"Malicious script patterns detected: {', '.join(hits)}")

            external_fetch = re.findall(
                r"""(?:fetch|XMLHttpRequest|sendBeacon)\s*\(\s*['"]([^'"]+)['"]""", script
            )
            for endpoint in external_fetch:
                parsed_ep = urllib.parse.urlparse(endpoint)
                if parsed_ep.netloc:
                    result.exfiltration_endpoints.append({
                        "type": "js_fetch",
                        "destination": endpoint,
                        "host": parsed_ep.netloc,
                    })
                    result.indicators.append(f"JavaScript data exfiltration endpoint: {endpoint}")

    def _detect_ui_cloning(self, html: str, result: URLAnalysisResult) -> None:
        brand_assets = {
            "paypal": ["paypal.com/assets", "paypalobjects.com"],
            "amazon": ["amazon.com/gp", "ssl-images-amazon.com"],
            "apple": ["apple.com/ac/globalnav", "applecdn.net"],
            "google": ["accounts.google.com", "gstatic.com"],
            "microsoft": ["microsoftonline.com", "live.com/login"],
        }

        for brand, assets in brand_assets.items():
            for asset in assets:
                if asset in html:
                    result.indicators.append(
                        f"UI Cloning detected — loading assets from {brand.title()} ({asset})"
                    )

        iframe_srcs = re.findall(r'<iframe[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in iframe_srcs:
            if src.startswith("http"):
                result.indicators.append(f"Hidden iframe detected pointing to: {src}")
                result.exfiltration_endpoints.append({"type": "iframe", "destination": src})

    def _detect_tracking_pixels(self, html: str, result: URLAnalysisResult) -> None:
        pixel_pattern = re.compile(
            r'<img[^>]+(?:width\s*=\s*["\']?1["\']?|height\s*=\s*["\']?1["\']?)[^>]*src\s*=\s*["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        for match in pixel_pattern.finditer(html):
            src = match.group(1)
            result.indicators.append(f"Tracking pixel detected: {src}")
            result.exfiltration_endpoints.append({"type": "tracking_pixel", "destination": src})

    def _calculate_threat_score(self, result: URLAnalysisResult) -> None:
        score = 0

        weights = {
            "Suspicious TLD": 15,
            "bare IP address": 20,
            "Brand impersonation": 25,
            "Homograph": 30,
            "@ symbol": 15,
            "Excessively long URL": 5,
            "Phishing keywords": 10,
            "hyphens in domain": 5,
            "Non-standard port": 10,
            "DNS resolution failed": 20,
            "No HTTPS": 15,
            "SSL certificate CN mismatch": 20,
            "Invalid SSL certificate": 20,
            "Free/automated SSL": 5,
            "Redirect detected": 10,
            "external domain": 30,
            "credential harvesting": 25,
            "Malicious script": 20,
            "UI Cloning": 25,
            "Hidden iframe": 15,
            "Tracking pixel": 5,
            "exfiltration": 15,
        }

        for indicator in result.indicators:
            for key, weight in weights.items():
                if key.lower() in indicator.lower():
                    score += weight
                    break

        score = min(score, 100)
        result.threat_score = score

        if score >= 80:
            result.verdict = "MALICIOUS"
        elif score >= 60:
            result.verdict = "HIGH_RISK"
        elif score >= 30:
            result.verdict = "SUSPICIOUS"
        elif score > 0:
            result.verdict = "LOW_RISK"
        else:
            result.verdict = "CLEAN"

        logger.info(
            f"URL analysis complete — score: {score}/100 verdict: {result.verdict}",
            module="URL_ANALYZER",
        )
