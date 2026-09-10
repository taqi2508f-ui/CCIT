"""
CCIT Email Parser Module
Custom phishing email detection engine.
Analyzes headers, SPF/DKIM/DMARC, suspicious links, dangerous attachments, and tracking pixels.
No external mail-security libraries used — all logic is built in-house.
"""

import email
import email.policy
import hashlib
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from email.header import decode_header
from typing import Optional

from modules.logger import logger
from modules.threat_scorer import ThreatScorer


DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".ps1", ".ps2", ".hta",
    ".jar", ".reg", ".dll", ".sys", ".cpl", ".inf", ".lnk", ".zip",
    ".7z", ".rar", ".iso", ".img",
}

PHISHING_BODY_PATTERNS = [
    r"verify\s+your\s+account",
    r"confirm\s+your\s+(email|identity|password)",
    r"your\s+account\s+(has\s+been|will\s+be)\s+(suspended|locked|disabled)",
    r"click\s+here\s+to\s+(verify|confirm|update)",
    r"update\s+your\s+(billing|payment|credit\s+card)",
    r"unusual\s+(sign-?in|login|activity)",
    r"security\s+(alert|notice|warning)",
    r"limited\s+time\s+offer",
    r"act\s+now\s+or",
    r"your\s+password\s+(will\s+expire|has\s+expired)",
    r"dear\s+(customer|user|member|valued)",
    r"congratulations.*won",
    r"\$\d+\s*(million|thousand|reward|prize)",
]

KNOWN_PHISHING_DOMAINS = {
    "amaz0n", "paypa1", "microsooft", "g00gle", "faceb00k",
    "bankofamerica-secure", "chase-verify", "irs-refund", "wellsfargo-alert",
}


@dataclass
class EmailAnalysisResult:
    raw_email: str = ""
    subject: str = ""
    sender_display: str = ""
    sender_email: str = ""
    reply_to: str = ""
    recipient: str = ""
    date: str = ""
    message_id: str = ""
    threat_score: int = 0
    verdict: str = "UNKNOWN"
    headers: dict = field(default_factory=dict)
    spf_result: dict = field(default_factory=dict)
    dkim_result: dict = field(default_factory=dict)
    dmarc_result: dict = field(default_factory=dict)
    suspicious_links: list[dict] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    tracking_pixels: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    body_text: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None


class EmailParser:
    """
    Full phishing email analysis engine.
    Supports raw RFC 2822 email strings or .eml file paths.
    """

    def __init__(self) -> None:
        self.scorer = ThreatScorer()

    def analyze_raw(self, raw_email: str) -> EmailAnalysisResult:
        result = EmailAnalysisResult(raw_email=raw_email)
        logger.info("Analyzing email headers and body", module="EMAIL_PARSER")
        try:
            msg = email.message_from_string(raw_email, policy=email.policy.default)
            self._extract_headers(msg, result)
            self._check_spf(result)
            self._check_dkim(result)
            self._check_dmarc(result)
            self._analyze_sender(result)
            self._extract_body_and_links(msg, result)
            self._scan_attachments(msg, result)
            self._calculate_score(result)
        except Exception as exc:
            result.error = str(exc)
            logger.error(f"Email analysis error: {exc}", module="EMAIL_PARSER")
        return result

    def analyze_file(self, file_path: str) -> EmailAnalysisResult:
        try:
            with open(file_path, "r", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            res = EmailAnalysisResult()
            res.error = str(exc)
            return res
        result = self.analyze_raw(raw)
        return result

    def analyze_demo(self) -> EmailAnalysisResult:
        """Return a realistic demo result for UI demonstration."""
        demo_raw = (
            "From: \"PayPal Security\" <security@paypa1-confirm.com>\n"
            "Reply-To: collect@evil-harvest.ru\n"
            "To: victim@example.com\n"
            "Subject: =?utf-8?b?VXJnZW50OiBWZXJpZnkgeW91ciBhY2NvdW50?=\n"
            "Date: Mon, 05 Jan 2026 03:22:11 +0000\n"
            "Message-ID: <phish-001@paypa1-confirm.com>\n"
            "X-Mailer: PhishKit/3.2\n"
            "Received: from [185.220.101.45] by mail.evil-harvest.ru\n\n"
            "Dear Customer,\n\n"
            "Your PayPal account has been suspended due to unusual activity.\n"
            "Please click here to verify your account immediately:\n"
            "http://paypa1-confirm.com/verify?token=abc123evil\n\n"
            "Failure to verify within 24 hours will result in permanent suspension.\n\n"
            "Regards,\nPayPal Security Team\n"
        )
        return self.analyze_raw(demo_raw)

    def _decode_header_value(self, value: str | None) -> str:
        if not value:
            return ""
        decoded_parts = decode_header(value)
        result_parts = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                try:
                    result_parts.append(part.decode(charset or "utf-8", errors="replace"))
                except Exception:
                    result_parts.append(part.decode("latin-1", errors="replace"))
            else:
                result_parts.append(str(part))
        return " ".join(result_parts).strip()

    def _extract_headers(self, msg: email.message.Message, result: EmailAnalysisResult) -> None:
        result.subject = self._decode_header_value(msg.get("Subject"))
        from_raw = self._decode_header_value(msg.get("From", ""))
        result.sender_display, result.sender_email = self._parse_address(from_raw)
        result.reply_to = self._decode_header_value(msg.get("Reply-To", ""))
        result.recipient = self._decode_header_value(msg.get("To", ""))
        result.date = self._decode_header_value(msg.get("Date", ""))
        result.message_id = msg.get("Message-ID", "")

        result.headers = {
            "Subject":    result.subject,
            "From":       from_raw,
            "Reply-To":   result.reply_to,
            "To":         result.recipient,
            "Date":       result.date,
            "Message-ID": result.message_id,
            "X-Mailer":   msg.get("X-Mailer", ""),
            "Received":   msg.get("Received", ""),
            "X-Originating-IP": msg.get("X-Originating-IP", ""),
            "Authentication-Results": msg.get("Authentication-Results", ""),
        }

    def _parse_address(self, addr_str: str) -> tuple[str, str]:
        match = re.match(r'^(.*?)\s*<([^>]+)>', addr_str)
        if match:
            return match.group(1).strip().strip('"'), match.group(2).strip()
        if "@" in addr_str:
            return addr_str.strip(), addr_str.strip()
        return addr_str.strip(), ""

    def _check_spf(self, result: EmailAnalysisResult) -> None:
        auth_results = result.headers.get("Authentication-Results", "").lower()
        received = result.headers.get("Received", "")

        spf_pass = "spf=pass" in auth_results
        spf_fail = "spf=fail" in auth_results or "spf=softfail" in auth_results
        spf_none = "spf=none" in auth_results

        result.spf_result = {
            "pass": spf_pass,
            "fail": spf_fail,
            "none": spf_none,
            "raw": auth_results,
        }

        if spf_fail:
            result.indicators.append("SPF check FAILED — sender IP not authorized for this domain")
        elif spf_none:
            result.indicators.append("SPF record not found — domain has no sending policy")
        elif not (spf_pass or spf_fail or spf_none):
            sender_domain = result.sender_email.split("@")[-1] if "@" in result.sender_email else ""
            if sender_domain:
                try:
                    socket.getaddrinfo(sender_domain, None)
                except socket.gaierror:
                    result.spf_result["domain_not_found"] = True
                    result.indicators.append(f"Sender domain does not exist: {sender_domain}")

    def _check_dkim(self, result: EmailAnalysisResult) -> None:
        auth_results = result.headers.get("Authentication-Results", "").lower()
        dkim_sig = result.headers.get("DKIM-Signature", "")

        dkim_pass = "dkim=pass" in auth_results
        dkim_fail = "dkim=fail" in auth_results
        dkim_none = not dkim_sig and not dkim_pass and not dkim_fail

        result.dkim_result = {
            "pass": dkim_pass,
            "fail": dkim_fail,
            "missing": dkim_none,
        }

        if dkim_fail:
            result.indicators.append("DKIM signature FAILED — email content may have been tampered with")
        elif dkim_none:
            result.indicators.append("DKIM signature missing — email cannot be cryptographically verified")

    def _check_dmarc(self, result: EmailAnalysisResult) -> None:
        auth_results = result.headers.get("Authentication-Results", "").lower()
        dmarc_pass = "dmarc=pass" in auth_results
        dmarc_fail = "dmarc=fail" in auth_results
        dmarc_none = "dmarc=none" in auth_results

        result.dmarc_result = {
            "pass": dmarc_pass,
            "fail": dmarc_fail,
            "none": dmarc_none,
        }

        if dmarc_fail:
            result.indicators.append("DMARC policy FAILED — email is not aligned with domain policy")
        elif dmarc_none:
            result.indicators.append("DMARC record not configured — open to spoofing")

    def _analyze_sender(self, result: EmailAnalysisResult) -> None:
        sender_email = result.sender_email.lower()
        sender_display = result.sender_display.lower()
        reply_to = result.reply_to.lower()

        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

        for phish_domain in KNOWN_PHISHING_DOMAINS:
            if phish_domain in sender_domain:
                result.indicators.append(
                    f"Known phishing domain pattern in sender: {sender_domain}"
                )

        known_brands = ["paypal", "amazon", "apple", "microsoft", "google", "facebook",
                        "netflix", "chase", "wellsfargo", "irs", "ebay"]
        for brand in known_brands:
            if brand in sender_display and brand not in sender_domain:
                result.indicators.append(
                    f"Display name impersonates '{brand}' but sender domain is '{sender_domain}'"
                )

        if reply_to and "@" in reply_to:
            reply_domain = reply_to.split("@")[-1].strip(">")
            if sender_domain and reply_domain != sender_domain:
                result.indicators.append(
                    f"Reply-To domain '{reply_domain}' differs from sender domain '{sender_domain}'"
                )

        suspicious_chars = re.findall(r"[^\x00-\x7F]", sender_email)
        if suspicious_chars:
            result.indicators.append(
                f"Non-ASCII characters in sender address: {''.join(suspicious_chars)}"
            )

        numbers_in_domain = re.findall(r"\d", sender_domain)
        if len(numbers_in_domain) > 2:
            result.indicators.append(f"Excessive digits in sender domain: {sender_domain}")

        x_mailer = result.headers.get("X-Mailer", "")
        if any(kw in x_mailer.lower() for kw in ["phish", "spam", "bulk", "mass"]):
            result.indicators.append(f"Suspicious X-Mailer header: {x_mailer}")

    def _extract_body_and_links(self, msg: email.message.Message, result: EmailAnalysisResult) -> None:
        body_text = ""
        html_body = ""

        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body_text += part.get_content()
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    html_body += str(part.get_payload(decode=True) or b"", "utf-8", errors="replace")
                except Exception:
                    pass

        result.body_text = body_text[:2000]

        combined = body_text + html_body
        for pattern in PHISHING_BODY_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                clean_pattern = pattern.replace(r"\s+", " ")
                result.indicators.append(
                    f"Phishing body pattern: '{clean_pattern}'"
                )

        url_pattern = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
        urls = url_pattern.findall(combined)

        for url in set(urls):
            link_info = self._assess_link(url)
            if link_info["suspicious"]:
                result.suspicious_links.append(link_info)
                result.indicators.append(
                    f"Suspicious link in body: {url[:80]} — {', '.join(link_info['reasons'])}"
                )

        pixel_pattern = re.compile(
            r'<img[^>]+(?:width\s*=\s*["\']?1["\']?|height\s*=\s*["\']?1["\']?)[^>]*/?>',
            re.IGNORECASE,
        )
        for match in pixel_pattern.finditer(html_body):
            src_match = re.search(r'src\s*=\s*["\']([^"\']+)["\']', match.group(), re.IGNORECASE)
            if src_match:
                result.tracking_pixels.append(src_match.group(1))
                result.indicators.append(f"Email tracking pixel detected: {src_match.group(1)[:80]}")

    def _assess_link(self, url: str) -> dict:
        reasons: list[str] = []
        suspicious = False

        url_lower = url.lower()

        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                      "is.gd", "buff.ly", "adf.ly", "tiny.cc"]
        if any(s in url_lower for s in shorteners):
            reasons.append("URL shortener (hides final destination)")
            suspicious = True

        for phish_domain in KNOWN_PHISHING_DOMAINS:
            if phish_domain in url_lower:
                reasons.append(f"Known phishing domain: {phish_domain}")
                suspicious = True

        try:
            import ipaddress
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            ipaddress.ip_address(host)
            reasons.append(f"Link uses bare IP address: {host}")
            suspicious = True
        except (ValueError, Exception):
            pass

        if not url.startswith("https://"):
            reasons.append("Link uses HTTP (not encrypted)")

        odd_chars = re.findall(r"[@%]{2,}", url)
        if odd_chars:
            reasons.append("Suspicious character sequences in URL")
            suspicious = True

        return {"url": url, "suspicious": suspicious or bool(reasons), "reasons": reasons}

    def _scan_attachments(self, msg: email.message.Message, result: EmailAnalysisResult) -> None:
        for part in msg.walk():
            disposition = part.get_content_disposition()
            if disposition not in ("attachment", "inline"):
                continue

            filename = part.get_filename() or "unknown"
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True) or b""
            size = len(payload)

            ext = ""
            dot_idx = filename.rfind(".")
            if dot_idx != -1:
                ext = filename[dot_idx:].lower()

            dangerous = ext in DANGEROUS_EXTENSIONS
            double_ext = filename.count(".") > 1
            hash_sha256 = hashlib.sha256(payload).hexdigest() if payload else ""

            attachment_info = {
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size,
                "extension": ext,
                "dangerous_extension": dangerous,
                "double_extension": double_ext,
                "sha256": hash_sha256,
                "suspicious": dangerous or double_ext,
            }
            result.attachments.append(attachment_info)

            if dangerous:
                result.indicators.append(
                    f"Dangerous attachment: '{filename}' ({ext} type is commonly malicious)"
                )
            if double_ext:
                result.indicators.append(
                    f"Double extension in attachment: '{filename}' — possible extension spoofing"
                )

    def _calculate_score(self, result: EmailAnalysisResult) -> None:
        score = 0
        weights = {
            "SPF check FAILED": 18,
            "SPF record not found": 8,
            "DKIM signature FAILED": 16,
            "DKIM signature missing": 10,
            "DMARC policy FAILED": 14,
            "DMARC record not configured": 8,
            "phishing domain": 22,
            "Display name impersonates": 20,
            "Reply-To domain": 15,
            "Non-ASCII characters": 18,
            "Excessive digits": 8,
            "Phishing body pattern": 10,
            "Suspicious link": 20,
            "tracking pixel": 5,
            "Dangerous attachment": 30,
            "Double extension": 15,
            "does not exist": 18,
        }

        for indicator in result.indicators:
            for key, weight in weights.items():
                if key.lower() in indicator.lower():
                    score += weight
                    break

        result.threat_score = min(score, 100)

        if result.threat_score >= 80:
            result.verdict = "PHISHING"
        elif result.threat_score >= 60:
            result.verdict = "HIGH_RISK"
        elif result.threat_score >= 30:
            result.verdict = "SUSPICIOUS"
        elif result.threat_score > 0:
            result.verdict = "LOW_RISK"
        else:
            result.verdict = "CLEAN"

        logger.info(
            f"Email analysis complete — score: {result.threat_score}/100, verdict: {result.verdict}",
            module="EMAIL_PARSER",
        )
