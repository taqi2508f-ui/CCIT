"""
CCIT Report Generator Module
Exports scan results to HTML and PDF formats.
HTML reports are self-contained with embedded CSS. PDF is generated via html2pdf or fallback.
"""

import json
import os
from datetime import datetime
from typing import Any

from modules.logger import logger


REPORT_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #c0c0c0; }
.container { max-width: 1100px; margin: 0 auto; padding: 30px; }
header { border-bottom: 2px solid #00FF41; padding-bottom: 20px; margin-bottom: 30px; }
.logo { font-size: 28px; color: #00FF41; font-weight: bold; letter-spacing: 4px; }
.logo span { color: #FF0055; }
.meta { color: #666; font-size: 12px; margin-top: 8px; }
h2 { color: #00FF41; font-size: 16px; letter-spacing: 2px; margin: 20px 0 12px; border-left: 3px solid #00FF41; padding-left: 10px; }
h3 { color: #88FF88; font-size: 13px; margin: 15px 0 8px; }
.score-box { display: inline-block; padding: 12px 24px; border-radius: 4px; font-size: 32px; font-weight: bold; margin: 10px 0; }
.verdict-CLEAN     { background: #001a00; color: #00FF41; border: 1px solid #00FF41; }
.verdict-LOW_RISK  { background: #1a1a00; color: #AAFF00; border: 1px solid #AAFF00; }
.verdict-SUSPICIOUS { background: #1a0e00; color: #FFAA00; border: 1px solid #FFAA00; }
.verdict-HIGH_RISK { background: #1a0500; color: #FF6600; border: 1px solid #FF6600; }
.verdict-PHISHING  { background: #1a0000; color: #FF0055; border: 1px solid #FF0055; }
.verdict-MALICIOUS { background: #1a0000; color: #FF0055; border: 1px solid #FF0055; }
.verdict-CRITICAL  { background: #1a001a; color: #FF00FF; border: 1px solid #FF00FF; }
.verdict-HIGH_RISK, .verdict-PHISHING, .verdict-MALICIOUS { animation: none; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 12px; }
th { background: #001a00; color: #00FF41; padding: 8px 12px; text-align: left; border: 1px solid #003300; }
td { padding: 7px 12px; border: 1px solid #1a1a1a; vertical-align: top; }
tr:nth-child(even) td { background: #0d0d0d; }
.indicator { padding: 6px 10px; margin: 4px 0; background: #0d0d0d; border-left: 3px solid #FF6600; font-size: 12px; color: #ffcc88; }
.indicator.critical { border-left-color: #FF0055; color: #ff8888; }
.indicator.info { border-left-color: #00FF41; color: #88ff88; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 2px; font-size: 11px; margin: 2px; }
.tag-high { background: #3a0000; color: #FF6600; border: 1px solid #FF6600; }
.tag-medium { background: #2a1a00; color: #FFAA00; border: 1px solid #FFAA00; }
.tag-low { background: #001a00; color: #00FF41; border: 1px solid #00FF41; }
footer { border-top: 1px solid #1a1a1a; margin-top: 40px; padding-top: 15px; color: #333; font-size: 11px; text-align: center; }
.progress-bar { background: #111; border: 1px solid #333; border-radius: 2px; height: 12px; width: 100%; }
.progress-fill { height: 12px; border-radius: 2px; }
pre { background: #080808; border: 1px solid #1a1a1a; padding: 12px; overflow-x: auto; font-size: 11px; color: #888; }
"""


class ReportGenerator:
    """Generates HTML and plain-text reports from scan result objects."""

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_html(self, scan_type: str, result: Any, title: str = "") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ccit_{scan_type}_{timestamp}.html"
        file_path = os.path.join(self.output_dir, filename)

        html = self._build_html(scan_type, result, title)

        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        logger.info(f"HTML report saved: {file_path}", module="REPORT_GENERATOR")
        return file_path

    def generate_json(self, scan_type: str, result: Any, title: str = "") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ccit_{scan_type}_{timestamp}.json"
        file_path = os.path.join(self.output_dir, filename)

        data = {
            "report_title": title or f"CCIT {scan_type.title()} Report",
            "generated_at": datetime.now().isoformat(),
            "scan_type": scan_type,
            "result": self._serialize(result),
        }

        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        logger.info(f"JSON report saved: {file_path}", module="REPORT_GENERATOR")
        return file_path

    def _build_html(self, scan_type: str, result: Any, title: str) -> str:
        verdict = getattr(result, "verdict", "UNKNOWN")
        score = getattr(result, "threat_score", 0)
        indicators = getattr(result, "indicators", [])
        target = getattr(result, "url",
                  getattr(result, "file_path",
                  getattr(result, "domain",
                  getattr(result, "sender_email", "N/A"))))

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        sections_html = self._build_sections(scan_type, result)

        bar_color = "#00FF41" if score < 30 else ("#FFAA00" if score < 60 else ("#FF6600" if score < 80 else "#FF0055"))

        indicators_html = ""
        for ind in indicators:
            cls = "critical" if any(w in ind.lower() for w in ["malicious", "critical", "exfil", "ransomware"]) else "info" if any(w in ind.lower() for w in ["clean", "pass"]) else ""
            indicators_html += f'<div class="indicator {cls}">{self._escape(ind)}</div>\n'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CCIT Report — {self._escape(title or scan_type)}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo">CYBER <span>CRIME</span> INVESTIGATION TOOL</div>
    <div class="meta">CCIT v1.0.0 &nbsp;|&nbsp; {now} &nbsp;|&nbsp; Scan Type: {scan_type.upper()}</div>
  </header>

  <h2>EXECUTIVE SUMMARY</h2>
  <table>
    <tr><th>Target</th><td>{self._escape(str(target))}</td></tr>
    <tr><th>Verdict</th><td><span class="score-box verdict-{verdict}">{verdict}</span></td></tr>
    <tr><th>Threat Score</th><td>
      <div class="progress-bar"><div class="progress-fill" style="width:{score}%;background:{bar_color};"></div></div>
      <b style="color:{bar_color}">{score}/100</b>
    </td></tr>
    <tr><th>Analysis Time</th><td>{now}</td></tr>
    <tr><th>Total Indicators</th><td>{len(indicators)}</td></tr>
  </table>

  <h2>THREAT INDICATORS ({len(indicators)})</h2>
  {indicators_html if indicators_html else '<p style="color:#666">No threat indicators detected.</p>'}

  {sections_html}

  <footer>
    Generated by CCIT v1.0.0 &nbsp;|&nbsp; For authorized cybersecurity investigation use only.
    &nbsp;|&nbsp; All analysis is defensive and ethical. Do not use for offensive purposes.
  </footer>
</div>
</body>
</html>"""

    def _build_sections(self, scan_type: str, result: Any) -> str:
        sections = ""

        if scan_type == "phishing_url":
            ssl = getattr(result, "ssl_info", {})
            dns = getattr(result, "dns_info", {})
            redirects = getattr(result, "redirects", [])
            forms = getattr(result, "form_actions", [])
            scripts = getattr(result, "suspicious_scripts", [])
            exfil = getattr(result, "exfiltration_endpoints", [])

            if ssl:
                sections += f"""<h2>SSL / TLS ANALYSIS</h2>
<table>
  <tr><th>Has HTTPS</th><td>{'Yes' if ssl.get('has_ssl') else 'No'}</td></tr>
  <tr><th>Valid Certificate</th><td>{'Yes' if ssl.get('valid') else 'No — ' + ssl.get('error','')}</td></tr>
  <tr><th>Subject CN</th><td>{self._escape(ssl.get('subject_cn',''))}</td></tr>
  <tr><th>Issuer</th><td>{self._escape(ssl.get('issuer_org',''))}</td></tr>
  <tr><th>Expires</th><td>{self._escape(ssl.get('not_after',''))}</td></tr>
</table>"""

            if dns:
                sections += f"""<h2>DNS RESOLUTION</h2>
<table>
  <tr><th>Hostname</th><td>{self._escape(dns.get('hostname',''))}</td></tr>
  <tr><th>Resolved IP</th><td>{self._escape(dns.get('resolved_ip',''))}</td></tr>
</table>"""

            if redirects:
                sections += f"<h2>REDIRECT CHAIN</h2><pre>{self._escape(chr(10).join(redirects))}</pre>"

            if exfil:
                rows = "".join(
                    f"<tr><td>{self._escape(e.get('type',''))}</td>"
                    f"<td>{self._escape(e.get('destination',''))}</td>"
                    f"<td>{self._escape(e.get('host',''))}</td></tr>"
                    for e in exfil
                )
                sections += f"""<h2>DATA EXFILTRATION ENDPOINTS</h2>
<table><tr><th>Type</th><th>Destination</th><th>Host</th></tr>{rows}</table>"""

        elif scan_type == "phishing_email":
            spf = getattr(result, "spf_result", {})
            dkim = getattr(result, "dkim_result", {})
            dmarc = getattr(result, "dmarc_result", {})
            links = getattr(result, "suspicious_links", [])
            attachments = getattr(result, "attachments", [])

            sections += f"""<h2>AUTHENTICATION CHECKS</h2>
<table>
  <tr><th>SPF</th><td>{'PASS' if spf.get('pass') else 'FAIL' if spf.get('fail') else 'NONE'}</td></tr>
  <tr><th>DKIM</th><td>{'PASS' if dkim.get('pass') else 'FAIL' if dkim.get('fail') else 'MISSING'}</td></tr>
  <tr><th>DMARC</th><td>{'PASS' if dmarc.get('pass') else 'FAIL' if dmarc.get('fail') else 'NONE'}</td></tr>
</table>"""

            if links:
                rows = "".join(
                    f"<tr><td>{self._escape(l.get('url','')[:80])}</td>"
                    f"<td>{', '.join(l.get('reasons',[]))}</td></tr>"
                    for l in links
                )
                sections += f"""<h2>SUSPICIOUS LINKS ({len(links)})</h2>
<table><tr><th>URL</th><th>Reasons</th></tr>{rows}</table>"""

            if attachments:
                rows = "".join(
                    f"<tr><td>{self._escape(a.get('filename',''))}</td>"
                    f"<td>{self._escape(a.get('extension',''))}</td>"
                    f"<td>{'⚠ DANGEROUS' if a.get('dangerous_extension') else 'OK'}</td>"
                    f"<td>{a.get('size_bytes',0):,}</td></tr>"
                    for a in attachments
                )
                sections += f"""<h2>ATTACHMENTS ({len(attachments)})</h2>
<table><tr><th>Filename</th><th>Extension</th><th>Risk</th><th>Size</th></tr>{rows}</table>"""

        elif scan_type in ("malware_file", "file_analysis"):
            entropy = getattr(result, "entropy", 0)
            packer = getattr(result, "packer_detected", None)
            sections_pe = getattr(result, "pe_sections", [])
            flags = getattr(result, "behavioral_flags", [])

            sections += f"""<h2>STATIC ANALYSIS</h2>
<table>
  <tr><th>File</th><td>{self._escape(getattr(result,'file_name',''))}</td></tr>
  <tr><th>Size</th><td>{getattr(result,'file_size',0):,} bytes</td></tr>
  <tr><th>SHA-256</th><td>{getattr(result,'sha256','')}</td></tr>
  <tr><th>MD5</th><td>{getattr(result,'md5','')}</td></tr>
  <tr><th>File Type</th><td>{getattr(result,'file_type','')}</td></tr>
  <tr><th>Entropy</th><td>{entropy:.4f} {'⚠ High — possible packing/encryption' if entropy > 7.0 else ''}</td></tr>
  <tr><th>Packer</th><td>{packer or 'None detected'}</td></tr>
</table>"""

            if flags:
                flags_html = "".join(f'<div class="indicator">{self._escape(f)}</div>' for f in flags)
                sections += f"<h2>BEHAVIORAL FLAGS</h2>{flags_html}"

        return sections

    def _escape(self, text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _serialize(self, obj: Any) -> Any:
        if hasattr(obj, "__dict__"):
            return {k: self._serialize(v) for k, v in obj.__dict__.items()}
        if isinstance(obj, list):
            return [self._serialize(i) for i in obj]
        if isinstance(obj, dict):
            return {k: self._serialize(v) for k, v in obj.items()}
        return obj
