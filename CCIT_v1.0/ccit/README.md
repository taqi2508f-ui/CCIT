# ◈ CCIT — Cyber Crime Investigation Tool v1.0.0

A professional Python desktop cybersecurity suite with a futuristic dark neon hacker UI.

---

## Features

| Module | Capability |
|---|---|
| **Phishing Scanner** | URL analysis — SSL check, redirect tracing, form/script extraction, exfiltration detection |
| **Email Detector** | RFC 2822 email phishing detection — header spoofing, SPF/DKIM/DMARC, malicious links, attachments |
| **Malware Analyzer** | Static file analysis — entropy, PE sections, packers, ransomware/keylogger/spyware behavioral flags |
| **Network Monitor** | Real-time connections, suspicious IP alerts, bandwidth charts, process attribution |
| **DNS Analyzer** | DNS record inspection, DGA detection, fast-flux analysis, SPF/DMARC extraction |
| **Signature Matcher** | Custom YARA-like engine with built-in threat rules across 6 categories |
| **Reports** | HTML and JSON report generation, scan history browser, export |
| **Settings** | Theme switching, scanner parameters, database management, offline mode |
| **Plugin Support** | Drop `.py` files in `ccit/plugins/` to extend functionality |

---

## Quick Start

### Windows

```
Double-click: build_exe.bat              (first time only — builds requirements_downloader.exe)
Double-click: requirements_downloader.exe (first time only — installs packages)
Double-click: CCIT.bat                    (to run)
```

### Linux / macOS

```bash
pip install -r ccit/requirements.txt
python ccit/main.py
```

---

## Requirements

- Python 3.10+ (tested on 3.14.2)
- PySide6 >= 6.6.0
- psutil >= 5.9.0 (optional — falls back to demo data if unavailable)
- requests >= 2.31.0
- chardet >= 5.2.0

---

## Directory Structure

```
ccit/
├── main.py                  ← Application entry point
├── requirements.txt
├── README.md
├── config/
│   └── config.json          ← Application settings
├── modules/                 ← All custom analysis engines
│   ├── logger.py
│   ├── database.py          ← SQLite scan history & settings
│   ├── url_analyzer.py      ← Phishing URL analysis
│   ├── email_parser.py      ← Email phishing detection
│   ├── file_monitor.py      ← Malware static analysis
│   ├── network_monitor.py   ← Live connection monitoring
│   ├── traffic_monitor.py   ← Bandwidth tracking
│   ├── dns_analyzer.py      ← DNS record inspection
│   ├── signature_matcher.py ← Threat rule engine
│   ├── report_generator.py  ← HTML/JSON export
│   ├── packet_inspector.py  ← Demo packet data
│   ├── threat_scorer.py     ← Unified scoring
│   └── update_checker.py    ← Version check (offline-safe)
├── ui/
│   ├── theme.py             ← 4 dark themes + stylesheet builder
│   ├── widgets.py           ← Reusable UI components
│   ├── sidebar.py           ← Navigation sidebar
│   ├── main_window.py       ← Root window + dashboard
│   ├── phishing_scanner.py
│   ├── email_detector.py
│   ├── malware_analyzer.py
│   ├── network_dashboard.py
│   ├── dns_view.py
│   ├── signatures_view.py
│   ├── reports_view.py
│   └── settings_panel.py
├── plugins/                 ← Drop .py plugins here
├── logs/                    ← Application + scan logs
├── database/                ← SQLite database files
└── reports/                 ← Generated HTML/JSON reports
```

---

## Themes

- `neon_dark`   — Green neon on black (default)
- `cyber_blue`  — Electric blue palette
- `red_alert`   — Red threat-room aesthetic
- `ghost_white` — Light/white mode

Change theme from **Settings → User Interface → Theme**.

---

## Plugin Development

Create `ccit/plugins/my_plugin.py`:

```python
class CCITPlugin:
    name = "My Plugin"
    description = "Custom analysis"
    version = "1.0"

    def run(self, context: dict) -> dict:
        return {"result": "ok"}
```

---

## Legal Notice

CCIT is designed **exclusively for ethical defensive cybersecurity investigation**.
Do not use for unauthorized access, offensive operations, or any illegal purpose.
