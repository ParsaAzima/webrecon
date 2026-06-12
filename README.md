<div align="center">

```
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Web Security Reconnaissance Tool**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-2.0-orange?style=flat-square)]()

A fast, modular web security scanner with sqlmap-style output — built for recon and security auditing.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Output](#-output)

</div>

---

## 📸 Preview

```
  ╔══════════════════════════════════════════════════════╗
  ║  🎯  TARGET   https://example.com                   ║
  ║  📡  STATUS   200     ⏱  RESPONSE 312 ms            ║
  ╚══════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════╗
║                 🔍  Technology Detection                  ║
╚══════════════════════════════════════════════════════════╝

  [*] Loading Wappalyzer DB [███████████████████████] 27/27 (100%)
  [+] Wappalyzer DB loaded — 7531 technologies

    ◈ CMS
      │  • WordPress
    ◈ Web Servers
      │  • Nginx
    ◈ Programming Languages
      │  • PHP

╔══════════════════════════════════════════════════════════╗
║                 🗂️  Sensitive File Scanner                ║
╚══════════════════════════════════════════════════════════╝

  [*] Scanning paths  [████████████████████░░░░░] 48/60 (80%)

  SEV          ST     SIZE       PATH                                   DESCRIPTION
  ──────────── ────── ────────── ────────────────────────────────────── ─────────────────────────
  🔴 CRITICAL   200    2.1 KB    /.env                                  Environment variables
  🟠 HIGH       403    0.0 KB    /wp-admin                              WordPress admin
  🟡 MEDIUM     200    1.4 KB    /api/v1                                API endpoint
```

---

## ✨ Features

- 🔍 **Technology Detection** — powered by the full Wappalyzer database (7500+ technologies)
- 🗂️ **Sensitive File Scanner** — 60+ paths checked concurrently with severity ratings
- 🔒 **Security Headers** — checks CSP, HSTS, X-Frame-Options, and more with a letter grade
- 🛡️ **CSP & CORS Analysis** — deep inspection including origin reflection tests
- 🔐 **SSL/TLS Analysis** — certificate expiry, weak protocols, cipher strength
- 🌐 **DNS Lookup** — A/AAAA/MX/NS/TXT/SOA/CAA/PTR with email security (SPF, DMARC, DKIM)
- 🤖 **Robots.txt Analysis** — extracts and live-checks suspicious disallowed paths
- 📄 **Body Analysis** — forms, CSRF detection, external JS, emails, HTML comments
- 🍪 **Cookie Inspector** — Secure/HttpOnly/SameSite flags per cookie
- 🖥️ **Server Fingerprinting** — extracts server/framework version headers
- 📊 **JSON Output** — full machine-readable report with `-o report.json`
- 🎨 **Colored Terminal UI** — sqlmap-style output with progress bars and severity badges

---

## 📦 Installation

```bash
git clone https://github.com/ParsaAzima/webrecon.git
cd webrecon
pip install -r requirements.txt
```

### Requirements

```
requests
dnspython
beautifulsoup4
```

Or install manually:

```bash
pip install requests dnspython beautifulsoup4
```

> **Windows users:** ANSI colors require Windows 10 build 1909+ or Windows Terminal. If colors don't render, use `--no-color`.

---

## 🚀 Usage

```bash
python scanner.py -u <URL> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL **(required)** | — |
| `-o, --output` | Save results to JSON file | — |
| `-t, --threads` | Threads for path scanner | `15` |
| `--timeout` | Request timeout in seconds | `10` |
| `--skip` | Skip one or more modules | — |
| `--no-color` | Disable colored output | — |

### Examples

```bash
# Basic scan
python scanner.py -u https://example.com

# Save full report to JSON
python scanner.py -u https://example.com -o report.json

# Faster scan with more threads
python scanner.py -u https://example.com -t 30

# Skip slow modules
python scanner.py -u https://example.com --skip wappalyzer dns

# No colors (for piping or logging)
python scanner.py -u https://example.com --no-color | tee scan.txt

# Full options
python scanner.py -u https://example.com -o report.json -t 25 --timeout 15
```

---

## 🧩 Modules

All modules run by default. Use `--skip <name>` to disable any of them.

| Module | Flag | Description |
|--------|------|-------------|
| Technology Detection | `wappalyzer` | Identify CMS, frameworks, servers via Wappalyzer DB |
| Security Headers | `headers` | Check for missing security response headers |
| CSP & CORS | `csp` | Analyze Content Security Policy and CORS config |
| Server Fingerprint | `fingerprint` | Extract version info from response headers |
| Cookies | `cookies` | Inspect cookie security flags |
| Body Analysis | `body` | Forms, links, JS files, emails, HTML comments |
| Sensitive Files | `files` | Scan 60+ paths for exposed configs and backups |
| Robots.txt | `robots` | Parse and live-check suspicious disallowed paths |
| SSL/TLS | `ssl` | Certificate validity, protocol version, cipher |
| DNS Lookup | `dns` | Full DNS records + SPF/DMARC/DKIM/CAA checks |

---

## 📊 Output

### Terminal

Color-coded severity system:

| Badge | Severity | Meaning |
|-------|----------|---------|
| 🔴 `CRITICAL` | Critical | Immediate risk — exposed credentials, git repo, backups |
| 🟠 `HIGH` | High | Significant risk — admin panels, PHP info, logs |
| 🟡 `MEDIUM` | Medium | Moderate risk — API endpoints, debug routes |
| 🟢 `INFO` | Info | Informational — robots.txt, sitemaps, security.txt |

### JSON Report

Using `-o report.json` saves a structured report:

```json
{
  "meta": {
    "url": "https://example.com",
    "status": 200,
    "response_ms": 312
  },
  "technologies": { ... },
  "ssl": {
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "bits": 256,
    "days_left": 142
  },
  "sensitive_files": [
    {
      "path": "/.env",
      "status": 200,
      "severity": "CRITICAL",
      "description": "Environment variables",
      "size": 2148
    }
  ],
  "security_headers": {
    "score": 4,
    "missing": ["Content-Security-Policy", "Permissions-Policy"]
  },
  "dns": { ... },
  "robots": { ... },
  "scan_duration_s": 18.4
}
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**.  
Only use it on systems you own or have explicit written permission to test.  
Unauthorized scanning may be illegal in your jurisdiction.  
The author is not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made by [ParsaAzima](https://github.com/ParsaAzima)

</div>
