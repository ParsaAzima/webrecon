#!/usr/bin/env python3
"""
WebRecon - Web Security Scanner
"""

import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import socket
from datetime import datetime
import dns.resolver
import dns.reversename
from bs4 import BeautifulSoup
import re
import json
import argparse
import sys
import time
import os

# ══════════════════════════════════════════════════════════════
#  ANSI Colors & Styles
# ══════════════════════════════════════════════════════════════

class C:
    """ANSI color codes"""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    BG_RED   = "\033[41m"
    BG_GREEN = "\033[42m"

    # Shorthand combos
    @staticmethod
    def red(s):     return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def green(s):   return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def yellow(s):  return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def blue(s):    return f"{C.BLUE}{s}{C.RESET}"
    @staticmethod
    def cyan(s):    return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def magenta(s): return f"{C.MAGENTA}{s}{C.RESET}"
    @staticmethod
    def bold(s):    return f"{C.BOLD}{s}{C.RESET}"
    @staticmethod
    def dim(s):     return f"{C.GRAY}{s}{C.RESET}"
    @staticmethod
    def gray(s):    return f"{C.GRAY}{s}{C.RESET}"
    @staticmethod
    def critical(s):return f"{C.BOLD}{C.RED}{s}{C.RESET}"
    @staticmethod
    def success(s): return f"{C.BOLD}{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def warn(s):    return f"{C.BOLD}{C.YELLOW}{s}{C.RESET}"

def no_color():
    """Disable colors (for --no-color flag)"""
    for attr in ['red','green','yellow','blue','cyan','magenta','bold','dim','gray','critical','success','warn']:
        setattr(C, attr, staticmethod(lambda s, *a, **kw: s))

# ══════════════════════════════════════════════════════════════
#  Banner & UI Helpers
# ══════════════════════════════════════════════════════════════

BANNER = r"""
{}{}
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{}{}                  Web Security Reconnaissance Tool  v2.0
{}                       github.com/your-handle/webrecon
{}"""

def print_banner():
    print(BANNER.format(
        C.BOLD, C.CYAN,
        C.RESET, C.BLUE,
        C.DIM,
        C.RESET,
    ))

def section(title, icon="", width=58):
    """Print a section header like sqlmap"""
    bar = "═" * width
    inner = f" {icon}  {title} " if icon else f" {title} "
    pad = (width - len(inner)) // 2
    print(f"\n{C.BOLD}{C.BLUE}╔{bar}╗{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}║{' ' * pad}{C.CYAN}{inner}{C.BLUE}{' ' * (width - pad - len(inner))}║{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}╚{bar}╝{C.RESET}")

def subsection(title, width=52):
    print(f"\n{C.BOLD}{C.BLUE}  ┌{'─'*width}┐{C.RESET}")
    inner = f"  {title}"
    print(f"{C.BOLD}{C.BLUE}  │{C.CYAN} {title:<{width-1}}{C.BLUE}│{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  └{'─'*width}┘{C.RESET}")

def divider(width=54, char="─"):
    print(f"  {C.GRAY}{char * width}{C.RESET}")

def info(msg):    print(f"  {C.CYAN}[*]{C.RESET} {msg}")
def ok(msg):      print(f"  {C.GREEN}[+]{C.RESET} {C.GREEN}{msg}{C.RESET}")
def warn(msg):    print(f"  {C.YELLOW}[!]{C.RESET} {C.YELLOW}{msg}{C.RESET}")
def error(msg):   print(f"  {C.RED}[✗]{C.RESET} {C.RED}{msg}{C.RESET}")
def found(msg):   print(f"  {C.GREEN}[✓]{C.RESET} {msg}")
def item(msg):    print(f"      {C.GRAY}├─{C.RESET} {msg}")
def item_last(msg): print(f"      {C.GRAY}└─{C.RESET} {msg}")

def severity_color(sev):
    if "CRITICAL" in sev: return C.critical(sev)
    if "HIGH"     in sev: return C.red(sev)
    if "MEDIUM"   in sev: return C.yellow(sev)
    if "INFO"     in sev: return C.green(sev)
    return sev

def status_badge(code):
    if code == 200:   return f"{C.BG_GREEN}{C.BOLD} {code} {C.RESET}"
    if code == 403:   return f"{C.BOLD}{C.YELLOW} {code} {C.RESET}"
    if code in (301,302): return f"{C.BOLD}{C.BLUE} {code} {C.RESET}"
    if code == 404:   return f"{C.GRAY} {code} {C.RESET}"
    return f"{C.BOLD} {code} {C.RESET}"

def progress_bar(current, total, width=35, prefix=""):
    pct  = current / total if total else 0
    done = int(pct * width)
    bar  = C.GREEN + "█" * done + C.GRAY + "░" * (width - done) + C.RESET
    sys.stdout.write(
        f"\r  {C.CYAN}[*]{C.RESET} {prefix} [{bar}] "
        f"{C.BOLD}{current}/{total}{C.RESET} "
        f"{C.GRAY}({pct*100:.0f}%){C.RESET}  "
    )
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")

# ══════════════════════════════════════════════════════════════
#  Config & Constants
# ══════════════════════════════════════════════════════════════

HEADERS = {
    "User-Agent"                : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept"                    : "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language"           : "en-US,en;q=0.9",
    "Accept-Encoding"           : "gzip, deflate, br",
    "Connection"                : "keep-alive",
    "Upgrade-Insecure-Requests" : "1",
    "Sec-Fetch-Dest"            : "document",
    "Sec-Fetch-Mode"            : "navigate",
    "Sec-Fetch-Site"            : "none",
    "Sec-Fetch-User"            : "?1",
    "Sec-CH-UA"                 : '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
    "Sec-CH-UA-Mobile"          : "?0",
    "Sec-CH-UA-Platform"        : '"Windows"',
    "Cache-Control"             : "max-age=0",
    "DNT"                       : "1",
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SENSITIVE_PATHS = {
    "/.env":                     ("CRITICAL", "Environment variables"),
    "/.env.local":               ("CRITICAL", "Environment variables (local)"),
    "/.env.production":          ("CRITICAL", "Environment variables (production)"),
    "/.env.backup":              ("CRITICAL", "Environment variables (backup)"),
    "/config.php":               ("CRITICAL", "PHP config file"),
    "/configuration.php":        ("CRITICAL", "Joomla config"),
    "/config/database.yml":      ("CRITICAL", "Rails DB credentials"),
    "/config/secrets.yml":       ("CRITICAL", "Rails secrets"),
    "/app/config/parameters.yml":("CRITICAL", "Symfony parameters"),
    "/wp-config.php":            ("CRITICAL", "WordPress config"),
    "/wp-config.php.bak":        ("CRITICAL", "WordPress config backup"),
    "/.git/HEAD":                ("CRITICAL", "Git repository exposed"),
    "/.git/config":              ("CRITICAL", "Git config exposed"),
    "/.svn/entries":             ("CRITICAL", "SVN repository exposed"),
    "/.DS_Store":                ("HIGH",     "macOS folder metadata"),
    "/backup.zip":               ("CRITICAL", "Backup archive"),
    "/backup.sql":               ("CRITICAL", "Database backup"),
    "/db.sql":                   ("CRITICAL", "Database dump"),
    "/database.sql":             ("CRITICAL", "Database dump"),
    "/dump.sql":                 ("CRITICAL", "Database dump"),
    "/backup.tar.gz":            ("CRITICAL", "Backup archive"),
    "/www.zip":                  ("CRITICAL", "Site backup"),
    "/old/index.php":            ("HIGH",     "Old version of site"),
    "/admin":                    ("HIGH",     "Admin panel"),
    "/admin/login":              ("HIGH",     "Admin login"),
    "/administrator":            ("HIGH",     "Joomla admin panel"),
    "/wp-admin":                 ("HIGH",     "WordPress admin"),
    "/wp-login.php":             ("HIGH",     "WordPress login"),
    "/phpmyadmin":               ("HIGH",     "phpMyAdmin"),
    "/pma":                      ("HIGH",     "phpMyAdmin (short)"),
    "/cpanel":                   ("HIGH",     "cPanel"),
    "/dashboard":                ("MEDIUM",   "Dashboard"),
    "/phpinfo.php":              ("CRITICAL", "PHP info page"),
    "/info.php":                 ("CRITICAL", "PHP info page"),
    "/test.php":                 ("HIGH",     "PHP test file"),
    "/debug":                    ("HIGH",     "Debug endpoint"),
    "/.well-known/security.txt": ("INFO",     "Security contact info"),
    "/server-status":            ("HIGH",     "Apache server status"),
    "/server-info":              ("HIGH",     "Apache server info"),
    "/logs/error.log":           ("CRITICAL", "Error log"),
    "/log/error.log":            ("CRITICAL", "Error log"),
    "/error.log":                ("CRITICAL", "Error log"),
    "/access.log":               ("CRITICAL", "Access log"),
    "/debug.log":                ("HIGH",     "Debug log"),
    "/storage/logs/laravel.log": ("CRITICAL", "Laravel log"),
    "/api":                      ("MEDIUM",   "API endpoint"),
    "/api/v1":                   ("MEDIUM",   "API v1"),
    "/api/v2":                   ("MEDIUM",   "API v2"),
    "/graphql":                  ("MEDIUM",   "GraphQL endpoint"),
    "/swagger":                  ("MEDIUM",   "Swagger API docs"),
    "/swagger-ui.html":          ("MEDIUM",   "Swagger UI"),
    "/api-docs":                 ("MEDIUM",   "API documentation"),
    "/robots.txt":               ("INFO",     "Robots file"),
    "/sitemap.xml":              ("INFO",     "Sitemap"),
    "/.htaccess":                ("HIGH",     "Apache config"),
    "/crossdomain.xml":          ("MEDIUM",   "Flash cross-domain policy"),
    "/humans.txt":               ("INFO",     "Humans file"),
    "/security.txt":             ("INFO",     "Security info"),
    "/package.json":             ("HIGH",     "Node.js package file"),
    "/composer.json":            ("HIGH",     "PHP composer file"),
    "/Dockerfile":               ("HIGH",     "Docker config"),
    "/docker-compose.yml":       ("HIGH",     "Docker compose config"),
}

SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "INFO":     "🟢",
}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

# Global results store (for JSON output)
RESULTS = {}

# ══════════════════════════════════════════════════════════════
#  Wappalyzer
# ══════════════════════════════════════════════════════════════

def load_wappalyzer_db():
    base_url      = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies"
    categories_url = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json"
    technologies   = {}

    try:
        cats = requests.get(categories_url, timeout=10).json()
    except:
        cats = {}

    files = [chr(i) for i in range(ord('a'), ord('z') + 1)] + ["_"]
    total = len(files)

    print()
    for i, f in enumerate(files, 1):
        progress_bar(i, total, prefix="Loading Wappalyzer DB")
        try:
            r = requests.get(f"{base_url}/{f}.json", timeout=10)
            if r.status_code == 200:
                technologies.update(r.json())
        except:
            pass

    ok(f"Wappalyzer DB loaded — {C.bold(str(len(technologies)))} technologies")
    return technologies, cats


def wappalyzer_detect(response, technologies, categories):
    headers  = {k.lower(): v for k, v in response.headers.items()}
    html     = response.text
    cookies  = {k.lower(): v for k, v in response.cookies.items()}
    detected = {}

    def match_pattern(pattern_str, value):
        if not value:
            return False
        parts   = pattern_str.split("\\;")
        pattern = parts[0]
        try:
            return bool(re.search(pattern, value, re.I))
        except re.error:
            return pattern.lower() in value.lower()

    for tech_name, tech_data in technologies.items():
        matched = False

        if "headers" in tech_data:
            for header_name, pattern in tech_data["headers"].items():
                if match_pattern(pattern, headers.get(header_name.lower(), "")):
                    matched = True; break

        if not matched and "html" in tech_data:
            patterns = tech_data["html"] if isinstance(tech_data["html"], list) else [tech_data["html"]]
            for p in patterns:
                if match_pattern(p, html):
                    matched = True; break

        if not matched and "cookies" in tech_data:
            for cookie_name, pattern in tech_data["cookies"].items():
                if cookie_name.lower() in cookies or match_pattern(pattern, cookies.get(cookie_name.lower(), "")):
                    matched = True; break

        if not matched and "scriptSrc" in tech_data:
            patterns = tech_data["scriptSrc"] if isinstance(tech_data["scriptSrc"], list) else [tech_data["scriptSrc"]]
            for p in patterns:
                if match_pattern(p, html):
                    matched = True; break

        if not matched and "meta" in tech_data:
            for meta_name, pattern in tech_data["meta"].items():
                meta_match = re.search(
                    f'<meta[^>]+name=["\']?{meta_name}["\']?[^>]+content=["\']?([^"\'> ]+)',
                    html, re.I
                )
                if meta_match and match_pattern(pattern, meta_match.group(1)):
                    matched = True; break

        if matched:
            cat_ids   = tech_data.get("cats", [])
            cat_names = [categories[str(c)]["name"] for c in cat_ids if str(c) in categories]
            detected[tech_name] = {
                "categories": cat_names or ["Unknown"],
                "website"   : tech_data.get("website", ""),
            }

    return detected


def print_wappalyzer_results(detected):
    if not detected:
        warn("Nothing detected")
        return

    by_category = {}
    for tech, info_d in detected.items():
        for cat in info_d["categories"]:
            by_category.setdefault(cat, []).append(tech)

    print(f"\n  {C.bold(C.cyan('Detected Technologies'))} {C.gray('─'*30 if hasattr(C,'gray') else '')}  "
          f"{C.green(str(len(detected)))} total\n")

    for category, techs in sorted(by_category.items()):
        print(f"    {C.BOLD}{C.MAGENTA}◈ {category}{C.RESET}")
        for t in sorted(techs):
            print(f"      {C.GRAY}│{C.RESET}  {C.CYAN}•{C.RESET} {t}")
        print()

    RESULTS["technologies"] = detected

# ══════════════════════════════════════════════════════════════
#  DNS Lookup
# ══════════════════════════════════════════════════════════════

def dns_lookup(url):
    hostname = urlparse(url).hostname
    RECORD_TYPES = {
        "A":     "IPv4 Address",
        "AAAA":  "IPv6 Address",
        "MX":    "Mail Server",
        "NS":    "Name Server",
        "TXT":   "Text Record",
        "CNAME": "Canonical Name",
        "SOA":   "Start of Authority",
        "CAA":   "CA Authorization",
    }

    info(f"Target: {C.bold(hostname)}")
    all_records = {}

    for record_type, description in RECORD_TYPES.items():
        try:
            answers = dns.resolver.resolve(hostname, record_type)
            records = []
            for rdata in answers:
                if record_type == "MX":
                    records.append(f"{rdata.exchange} {C.dim(f'(priority: {rdata.preference})')}")
                elif record_type == "SOA":
                    records.append(
                        f"Primary NS: {rdata.mname}  "
                        f"Serial: {rdata.serial}  "
                        f"Refresh: {rdata.refresh}s"
                    )
                elif record_type == "CAA":
                    records.append(f"{rdata.flags} {rdata.tag.decode()} {rdata.value.decode()}")
                else:
                    records.append(str(rdata))
            all_records[record_type] = records
            print(f"\n    {C.BOLD}{C.CYAN}{record_type}{C.RESET}  {C.GRAY}{description}{C.RESET}")
            for i, r in enumerate(records):
                connector = "└─" if i == len(records)-1 else "├─"
                print(f"      {C.GRAY}{connector}{C.RESET} {r}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            error(f"Domain not found: {hostname}")
            return None
        except dns.resolver.Timeout:
            warn(f"Timeout on {record_type} record")
        except Exception:
            pass

    # Reverse DNS
    print(f"\n    {C.BOLD}{C.CYAN}PTR{C.RESET}  {C.GRAY}Reverse DNS{C.RESET}")
    try:
        for ip in all_records.get("A", [])[:3]:
            rev = dns.reversename.from_address(ip)
            ptr = dns.resolver.resolve(rev, "PTR")
            for p in ptr:
                print(f"      {C.GRAY}└─{C.RESET} {ip} {C.GRAY}→{C.RESET} {C.GREEN}{p}{C.RESET}")
    except:
        print(f"      {C.GRAY}└─{C.RESET} {C.DIM}No PTR record found{C.RESET}")

    # Security Analysis
    divider()
    print(f"\n  {C.BOLD}Email Security Records{C.RESET}\n")

    # SPF
    spf_found = False
    for txt in all_records.get("TXT", []):
        if "v=spf1" in txt:
            spf_found = True
            raw = txt.replace(C.GRAY,"").replace(C.RESET,"")  # strip color for check
            if "~all" in raw:
                print(f"    {C.YELLOW}[~]{C.RESET}  SPF  {C.YELLOW}SoftFail (~all){C.RESET}")
            elif "-all" in raw:
                print(f"    {C.GREEN}[✓]{C.RESET}  SPF  {C.GREEN}HardFail (-all){C.RESET}")
            elif "+all" in raw:
                print(f"    {C.RED}[✗]{C.RESET}  SPF  {C.RED}DANGEROUS (+all) — allows any sender!{C.RESET}")
            else:
                print(f"    {C.YELLOW}[~]{C.RESET}  SPF  {C.YELLOW}Neutral policy{C.RESET}")
    if not spf_found:
        print(f"    {C.RED}[✗]{C.RESET}  SPF  {C.RED}Not configured — email spoofing risk!{C.RESET}")

    # DMARC
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{hostname}", "TXT")
        for r in dmarc:
            txt = str(r)
            if "v=DMARC1" in txt:
                if "p=reject"     in txt: print(f"    {C.GREEN}[✓]{C.RESET}  DMARC  {C.GREEN}Enforced (p=reject){C.RESET}")
                elif "p=quarantine" in txt: print(f"    {C.YELLOW}[~]{C.RESET}  DMARC  {C.YELLOW}Quarantine (p=quarantine){C.RESET}")
                elif "p=none"      in txt: print(f"    {C.YELLOW}[!]{C.RESET}  DMARC  {C.YELLOW}Not enforced (p=none){C.RESET}")
    except:
        print(f"    {C.RED}[✗]{C.RESET}  DMARC  {C.RED}Not configured{C.RESET}")

    # DKIM
    dkim_found = False
    for selector in ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{hostname}", "TXT")
            print(f"    {C.GREEN}[✓]{C.RESET}  DKIM   {C.GREEN}Found (selector: {selector}){C.RESET}")
            dkim_found = True
            break
        except:
            pass
    if not dkim_found:
        print(f"    {C.RED}[✗]{C.RESET}  DKIM   {C.RED}Not found (tried common selectors){C.RESET}")

    # CAA
    if "CAA" in all_records:
        print(f"    {C.GREEN}[✓]{C.RESET}  CAA    {C.GREEN}Configured{C.RESET}")
    else:
        print(f"    {C.YELLOW}[~]{C.RESET}  CAA    {C.YELLOW}Not set — any CA can issue certs{C.RESET}")

    # NS redundancy
    ns = all_records.get("NS", [])
    if len(ns) >= 2:
        print(f"    {C.GREEN}[✓]{C.RESET}  NS     {C.GREEN}{len(ns)} nameservers (redundancy OK){C.RESET}")
    elif len(ns) == 1:
        print(f"    {C.YELLOW}[!]{C.RESET}  NS     {C.YELLOW}Only 1 nameserver — no redundancy{C.RESET}")

    print(f"\n    {C.DIM}Record types found: {len(all_records)}{C.RESET}")
    RESULTS["dns"] = {k: [str(r) for r in v] for k, v in all_records.items()}
    return all_records

# ══════════════════════════════════════════════════════════════
#  SSL/TLS Analysis
# ══════════════════════════════════════════════════════════════

def analyze_ssl(url):
    hostname = urlparse(url).hostname
    port     = urlparse(url).port or 443

    if urlparse(url).scheme != "https":
        warn("Site uses HTTP — no SSL/TLS")
        return None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert    = tls.getpeercert()
                tls_ver = tls.version()
                cipher  = tls.cipher()

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
        days_left  = (not_after - datetime.utcnow()).days
        issuer     = dict(x[0] for x in cert["issuer"])
        subject    = dict(x[0] for x in cert["subject"])
        san_list   = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        # Certificate info
        print(f"\n  {C.BOLD}Certificate Info{C.RESET}")
        divider()
        print(f"    {'Domain':<18} {C.cyan(subject.get('commonName', '—'))}")
        print(f"    {'Issuer':<18} {issuer.get('organizationName', '—')}")
        print(f"    {'Valid From':<18} {not_before.strftime('%Y-%m-%d')}")
        print(f"    {'Valid Until':<18} {not_after.strftime('%Y-%m-%d')}")

        if   days_left < 0:    print(f"    {'Expires':<18} {C.critical(f'EXPIRED {abs(days_left)} days ago!')}")
        elif days_left <= 15:  print(f"    {'Expires':<18} {C.critical(f'CRITICAL — {days_left} days left')}")
        elif days_left <= 30:  print(f"    {'Expires':<18} {C.warn(f'WARNING — {days_left} days left')}")
        else:                  print(f"    {'Expires':<18} {C.green(f'{days_left} days left')}")

        # TLS
        print(f"\n  {C.BOLD}TLS Details{C.RESET}")
        divider()
        TLS_STATUS = {
            "TLSv1.3": C.green("✅ Excellent"),
            "TLSv1.2": C.green("✅ Good"),
            "TLSv1.1": C.yellow("🟠 Deprecated"),
            "TLSv1":   C.red("🔴 Insecure"),
            "SSLv3":   C.critical("🔴 Critically Insecure"),
            "SSLv2":   C.critical("🔴 Critically Insecure"),
        }
        print(f"    {'Version':<18} {tls_ver}  {TLS_STATUS.get(tls_ver, tls_ver)}")
        print(f"    {'Cipher':<18} {C.cyan(cipher[0])}")
        print(f"    {'Key Bits':<18} {cipher[2]} bits  "
              f"{'✅' if cipher[2] >= 128 else C.red('❌ Weak!')}")

        # SANs
        if san_list:
            print(f"\n  {C.BOLD}Subject Alternative Names{C.RESET}  {C.DIM}({len(san_list)} total){C.RESET}")
            divider()
            for san in san_list[:10]:
                print(f"    {C.GRAY}•{C.RESET} {san}")
            if len(san_list) > 10:
                print(f"    {C.DIM}... and {len(san_list) - 10} more{C.RESET}")

        # Security checks
        print(f"\n  {C.BOLD}Security Checks{C.RESET}")
        divider()
        checks = [
            ("TLS 1.3 Support",    tls_ver == "TLSv1.3",                   False),
            ("Strong Cipher",      cipher[2] >= 128,                        False),
            ("Wildcard Cert",      subject.get("commonName","").startswith("*"), True),
            ("Multi-Domain (SAN)", len(san_list) > 1,                       False),
            ("Cert Not Expired",   days_left > 0,                           False),
        ]
        for label, passed, is_warn in checks:
            if is_warn:
                icon = C.yellow("⚠️  WARN ") if passed else C.green("✅ PASS ")
            else:
                icon = C.green("✅ PASS ") if passed else C.red("❌ FAIL ")
            print(f"    {icon}  {label}")

        # Weak protocol check
        print(f"\n  {C.BOLD}Weak Protocol Check{C.RESET}")
        divider()
        for proto_name in ["TLSv1", "TLSv1.1"]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1 if proto_name == "TLSv1" else ssl.TLSVersion.TLSv1_1
                with socket.create_connection((hostname, port), timeout=5) as s:
                    with ctx.wrap_socket(s, server_hostname=hostname):
                        print(f"    {C.critical('❌ VULN ')}  {proto_name} is {C.red('ENABLED')} — insecure!")
            except:
                print(f"    {C.green('✅ SAFE ')}  {proto_name} is disabled")

        RESULTS["ssl"] = {
            "version": tls_ver,
            "cipher":  cipher[0],
            "bits":    cipher[2],
            "days_left": days_left,
            "san_count": len(san_list),
        }
        return cert

    except ssl.SSLCertVerificationError:
        error("SSL Certificate verification FAILED (untrusted / self-signed)")
    except ssl.SSLError as e:
        error(f"SSL Error: {e}")
    except socket.timeout:
        warn("Connection timed out")
    except Exception as e:
        warn(f"Error: {e}")
    return None

# ══════════════════════════════════════════════════════════════
#  Sensitive File Scanner
# ══════════════════════════════════════════════════════════════

def check_path(base_url, path, info_tuple, timeout=5):
    severity, description = info_tuple
    try:
        r = requests.get(
            base_url + path,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": HEADERS["User-Agent"]},
        )
        if r.status_code in (200, 403):
            return {
                "path":        path,
                "status":      r.status_code,
                "severity":    severity,
                "description": description,
                "size":        len(r.content),
            }
    except:
        pass
    return None


def scan_sensitive_files(url, max_workers=15):
    base_url = url.rstrip("/")
    found    = []
    paths    = list(SENSITIVE_PATHS.items())
    total    = len(paths)
    done     = 0

    print()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_path, base_url, path, info_tuple): path
            for path, info_tuple in paths
        }
        for future in as_completed(futures):
            done += 1
            progress_bar(done, total, prefix="Scanning paths ")
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: SEV_ORDER.get(x["severity"], 99))

    if found:
        print(f"\n  {C.bold(C.red(f'⚠  {len(found)} path(s) found!'))}\n")
        print(f"  {'SEV':<12} {'ST':<6} {'SIZE':<10} {'PATH':<38} DESCRIPTION")
        print(f"  {'─'*12} {'─'*6} {'─'*10} {'─'*38} {'─'*25}")

        for item_d in found:
            sev   = item_d["severity"]
            icon  = SEV_ICON.get(sev, "?")
            sz    = f"{item_d['size'] / 1024:.1f} KB"
            badge = status_badge(item_d["status"])
            sev_str = {
                "CRITICAL": C.critical(f"{icon} CRITICAL"),
                "HIGH":     C.red(f"{icon} HIGH    "),
                "MEDIUM":   C.yellow(f"{icon} MEDIUM  "),
                "INFO":     C.green(f"{icon} INFO    "),
            }.get(sev, sev)
            print(
                f"  {sev_str}  {badge}  "
                f"{C.DIM}{sz:<10}{C.RESET}"
                f"{C.CYAN}{item_d['path']:<38}{C.RESET}"
                f"{item_d['description']}"
            )
    else:
        ok("No sensitive files found")

    RESULTS["sensitive_files"] = found
    return found

# ══════════════════════════════════════════════════════════════
#  Security Headers
# ══════════════════════════════════════════════════════════════

def check_security_headers(headers):
    score  = 0
    issues = []
    print()
    for h in SECURITY_HEADERS:
        if h in headers:
            score += 1
            print(f"  {C.green('[✓]')}  {h}")
            print(f"       {C.DIM}{headers[h][:80]}{'...' if len(headers[h]) > 80 else ''}{C.RESET}")
        else:
            issues.append(h)
            print(f"  {C.red('[✗]')}  {C.red(h + '  ← MISSING')}")

    grade = score / len(SECURITY_HEADERS)
    grade_str = (
        C.green("A") if grade >= 0.9 else
        C.green("B") if grade >= 0.7 else
        C.yellow("C") if grade >= 0.5 else
        C.red("D")   if grade >= 0.3 else
        C.critical("F")
    )
    print(f"\n  {C.bold('Score:')} {score}/{len(SECURITY_HEADERS)}  Grade: {C.bold(grade_str)}")
    RESULTS["security_headers"] = {"score": score, "missing": issues}

# ══════════════════════════════════════════════════════════════
#  Robots.txt
# ══════════════════════════════════════════════════════════════

def parse_robots(url):
    base_url   = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    robots_url = f"{base_url}/robots.txt"

    try:
        response = requests.get(robots_url, timeout=10, headers=HEADERS)
        if response.status_code == 404:
            warn("robots.txt not found")
            return None
        if response.status_code != 200:
            warn(f"Unexpected status: {response.status_code}")
            return None

        lines   = response.text.splitlines()
        results = {"sitemaps": [], "user_agents": {}, "disallowed": [], "allowed": []}
        current_agent = "*"

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()

            if key == "user-agent":
                current_agent = value
                results["user_agents"].setdefault(current_agent, {"disallow": [], "allow": []})
            elif key == "disallow" and value:
                results["disallowed"].append(value)
                if current_agent in results["user_agents"]:
                    results["user_agents"][current_agent]["disallow"].append(value)
            elif key == "allow" and value:
                results["allowed"].append(value)
                if current_agent in results["user_agents"]:
                    results["user_agents"][current_agent]["allow"].append(value)
            elif key == "sitemap":
                results["sitemaps"].append(value)

        SUSPICIOUS_PATTERNS = [
            (r"admin",             "CRITICAL",  "Admin panel path"),
            (r"backup",            "CRITICAL",  "Backup directory"),
            (r"config",            "CRITICAL",  "Config file/directory"),
            (r"\.env",             "CRITICAL",  "Environment file"),
            (r"database|db",       "CRITICAL",  "Database related"),
            (r"private|secret",    "CRITICAL",  "Private/Secret path"),
            (r"api",               "HIGH",      "API endpoint"),
            (r"dev|staging|test",  "HIGH",      "Dev/Staging environment"),
            (r"login|signin",      "HIGH",      "Login page"),
            (r"upload",            "HIGH",      "Upload directory"),
            (r"\.git",             "CRITICAL",  "Git repository"),
            (r"phpinfo|info\.php", "CRITICAL",  "PHP info page"),
            (r"wp-admin|wp-login", "HIGH",      "WordPress admin"),
            (r"phpmyadmin|pma",    "CRITICAL",  "phpMyAdmin"),
            (r"\.sql|\.bak|\.zip", "CRITICAL",  "Sensitive file extension"),
        ]

        suspicious_found = []
        for path in results["disallowed"]:
            for pattern, sev, desc in SUSPICIOUS_PATTERNS:
                if re.search(pattern, path, re.I):
                    suspicious_found.append((path, sev, desc))
                    break

        # Print user agents
        print(f"\n  {C.bold('User Agents')}  {C.dim(str(len(results['user_agents'])) + ' found')}")
        for agent in results["user_agents"]:
            print(f"    {C.GRAY}•{C.RESET} {agent}")

        # Disallowed
        print(f"\n  {C.bold('Disallowed Paths')}  {C.dim(str(len(results['disallowed'])) + ' total')}")
        susp_paths = {p for p, *_ in suspicious_found}
        for path in results["disallowed"]:
            flag = f"  {C.yellow('← suspicious!')}" if path in susp_paths else ""
            print(f"    {C.GRAY}•{C.RESET} {path}{flag}")

        # Sitemaps
        if results["sitemaps"]:
            print(f"\n  {C.bold('Sitemaps')}")
            for s in results["sitemaps"]:
                print(f"    {C.GRAY}•{C.RESET} {C.cyan(s)}")

        # Suspicious with live check
        if suspicious_found:
            print(f"\n  {C.bold(C.red(f'⚠  {len(suspicious_found)} suspicious path(s) in robots.txt'))}")
            divider()
            for path, sev, desc in suspicious_found:
                icon = SEV_ICON.get(sev, "?")
                sev_c = C.critical if sev == "CRITICAL" else C.red if sev == "HIGH" else C.yellow
                print(f"\n    {sev_c(icon + ' ' + sev):<22}  {desc}")
                print(f"    {C.cyan(base_url + path)}")
                try:
                    r = requests.get(base_url + path, timeout=5, headers=HEADERS, allow_redirects=False)
                    LABELS = {
                        200: C.critical("🔴 ACCESSIBLE"),
                        403: C.yellow("🟡 Forbidden (exists)"),
                        401: C.yellow("🟡 Auth required"),
                        301: C.blue("🔵 Redirect"),
                        302: C.blue("🔵 Redirect"),
                        404: C.green("✅ Not found"),
                    }
                    print(f"    Status: {LABELS.get(r.status_code, C.dim(str(r.status_code)))}")
                except:
                    pass

        # Summary
        print(f"\n  {C.bold('Summary')}")
        print(f"    Disallowed: {len(results['disallowed'])}   "
              f"Allowed: {len(results['allowed'])}   "
              f"Sitemaps: {len(results['sitemaps'])}   "
              f"Suspicious: {C.red(str(len(suspicious_found))) if suspicious_found else C.green('0')}")

        RESULTS["robots"] = results
        return results

    except Exception as e:
        error(f"robots.txt error: {e}")
    return None

# ══════════════════════════════════════════════════════════════
#  CSP & CORS Analysis
# ══════════════════════════════════════════════════════════════

def analyze_csp_cors(response, url):
    headers = response.headers
    origin  = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # ── CSP ──────────────────────────────────────────────────────────
    print(f"\n  {C.bold('Content Security Policy (CSP)')}")
    divider()

    csp_header     = headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only")
    csp_report_only = "Content-Security-Policy-Report-Only" in headers
    csp_result     = {"enabled": False, "report_only": False, "directives": {}, "issues": []}

    if not csp_header:
        print(f"  {C.red('[✗]')}  {C.red('CSP not found')} — XSS protection missing!")
        csp_result["issues"].append("No CSP header")
    else:
        csp_result["enabled"]     = True
        csp_result["report_only"] = csp_report_only
        if csp_report_only:
            print(f"  {C.yellow('[~]')}  CSP found {C.yellow('(Report-Only — not enforced!)')}")
        else:
            print(f"  {C.green('[✓]')}  CSP found {C.green('(Enforced)')}")

        directives = {}
        for directive in csp_header.split(";"):
            directive = directive.strip()
            if not directive: continue
            parts = directive.split()
            if parts:
                directives[parts[0].lower()] = parts[1:]
        csp_result["directives"] = directives

        IMPORTANT_DIRECTIVES = [
            "default-src","script-src","style-src","img-src","connect-src",
            "frame-src","font-src","object-src","base-uri","form-action",
            "frame-ancestors","upgrade-insecure-requests","block-all-mixed-content",
        ]
        print(f"\n  {'Directive':<35} Values")
        divider()
        for d in IMPORTANT_DIRECTIVES:
            if d in directives:
                vals = " ".join(directives[d]) or "(empty)"
                print(f"  {C.green('[✓]')}  {C.cyan(d):<35} {C.DIM}{vals}{C.RESET}")
            else:
                print(f"  {C.GRAY}[–]  {d:<35} not set{C.RESET}")

        DANGEROUS = {
            "'unsafe-inline'": ("CRITICAL", "unsafe-inline allows inline scripts/styles (XSS risk)"),
            "'unsafe-eval'":   ("CRITICAL", "unsafe-eval allows eval() (XSS risk)"),
            "data:":           ("HIGH",     "data: URI scheme allowed"),
            "*":               ("CRITICAL", "Wildcard (*) — any source allowed"),
            "http:":           ("HIGH",     "http: allows insecure resources"),
        }
        print(f"\n  {C.bold('CSP Issues')}")
        issues_found = False
        for directive, values in directives.items():
            values_str = " ".join(values)
            for dangerous, (sev, msg) in DANGEROUS.items():
                if dangerous in values_str:
                    icon = SEV_ICON.get(sev, "!")
                    printer = C.critical if sev == "CRITICAL" else C.red
                    print(f"    {printer(icon + ' ' + msg)}")
                    print(f"    {C.DIM}→ in: {directive}{C.RESET}")
                    csp_result["issues"].append(f"{directive}: {dangerous}")
                    issues_found = True

        if "default-src" not in directives and "script-src" not in directives:
            print(f"    {C.critical('🔴 No default-src or script-src — scripts unrestricted!')}")
            csp_result["issues"].append("No script source restriction")
            issues_found = True
        if "object-src" not in directives:
            print(f"    {C.yellow('🟠 object-src not set — Flash/plugins may load')}")
            csp_result["issues"].append("object-src missing")
            issues_found = True
        if "base-uri" not in directives:
            print(f"    {C.yellow('🟠 base-uri not set — base tag injection possible')}")
            csp_result["issues"].append("base-uri missing")
            issues_found = True
        if "frame-ancestors" not in directives:
            print(f"    {C.yellow('🟡 frame-ancestors not set — clickjacking possible')}")
            csp_result["issues"].append("frame-ancestors missing")
            issues_found = True
        if not issues_found:
            ok("No major CSP issues found")

    # ── CORS ─────────────────────────────────────────────────────────
    print(f"\n  {C.bold('Cross-Origin Resource Sharing (CORS)')}")
    divider()

    cors_result = {"enabled": False, "issues": []}
    acao  = headers.get("Access-Control-Allow-Origin")
    acam  = headers.get("Access-Control-Allow-Methods")
    acah  = headers.get("Access-Control-Allow-Headers")
    acac  = headers.get("Access-Control-Allow-Credentials")
    acmax = headers.get("Access-Control-Max-Age")

    if not acao:
        print(f"  {C.GRAY}[–]  CORS not configured (no ACAO header){C.RESET}")
    else:
        cors_result["enabled"] = True
        print(f"    {'Allow-Origin':<22} {C.cyan(acao)}")
        if acam:  print(f"    {'Allow-Methods':<22} {acam}")
        if acah:  print(f"    {'Allow-Headers':<22} {acah}")
        if acac:  print(f"    {'Allow-Credentials':<22} {acac}")
        if acmax: print(f"    {'Max-Age':<22} {acmax}s")

        print(f"\n  {C.bold('CORS Issues')}")
        issues_found = False

        if acao == "*":
            print(f"    {C.critical('🔴 Allow-Origin: * — any domain can access!')}")
            cors_result["issues"].append("Wildcard origin")
            issues_found = True
        if acao == "*" and acac and acac.lower() == "true":
            print(f"    {C.critical('🔴 CRITICAL: Wildcard + Credentials=true!')}")
            cors_result["issues"].append("Wildcard with credentials")
            issues_found = True
        if acac and acac.lower() == "true" and acao != "*":
            print(f"    {C.yellow(f'🟡 Credentials allowed for: {acao}')}")
            cors_result["issues"].append(f"Credentials allowed for {acao}")
            issues_found = True
        if acam:
            dangerous_methods = [m for m in ["DELETE","PUT","PATCH"] if m in acam.upper()]
            if dangerous_methods:
                print(f"    {C.red('🟠 Dangerous methods: ' + ', '.join(dangerous_methods))}")
                cors_result["issues"].append(f"Dangerous methods: {dangerous_methods}")
                issues_found = True

        if not issues_found:
            ok("No major CORS issues found")

        # Origin reflection tests
        print(f"\n  {C.bold('CORS Origin Tests')}")
        test_origins = [
            ("null",                          "Null origin"),
            ("https://evil.com",              "Random domain"),
            (origin + ".evil.com",            "Suffix bypass"),
            ("https://evil" + urlparse(url).netloc, "Prefix bypass"),
        ]
        for test_origin, label in test_origins:
            try:
                r = requests.options(url, timeout=5, headers={**HEADERS, "Origin": test_origin})
                reflected = r.headers.get("Access-Control-Allow-Origin", "")
                if reflected == test_origin or reflected == "*":
                    print(f"    {C.critical('🔴 REFLECTED!')}  {label:<28} {C.dim(test_origin)}")
                    cors_result["issues"].append(f"Origin reflected: {test_origin}")
                else:
                    print(f"    {C.green('✅ safe    ')}  {label}")
            except:
                pass

    # Summary
    csp_score  = max(0, 10 - len(csp_result["issues"]) * 2)
    cors_score = max(0, 10 - len(cors_result["issues"]) * 3)
    total_score = (csp_score + cors_score) // 2
    def score_badge(s):
        if s >= 7: return C.green(f"{s}/10")
        if s >= 4: return C.yellow(f"{s}/10")
        return C.red(f"{s}/10")

    print(f"\n  {C.bold('CSP/CORS Score')}")
    divider()
    print(f"    CSP   {score_badge(csp_score)}")
    print(f"    CORS  {score_badge(cors_score)}")
    print(f"    Total {score_badge(total_score)}")

    RESULTS["csp_cors"] = {"csp": csp_result, "cors": cors_result}
    return {"csp": csp_result, "cors": cors_result}

# ══════════════════════════════════════════════════════════════
#  Body Analysis
# ══════════════════════════════════════════════════════════════

def analyze_body(response, url):
    soup    = BeautifulSoup(response.text, "html.parser")
    base    = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    size_kb = len(response.content) / 1024
    print(f"\n  {C.bold('Page Info')}")
    print(f"    {'Size':<18} {size_kb:.1f} KB")
    print(f"    {'Encoding':<18} {response.encoding}")

    # Meta
    title       = soup.find("title")
    description = soup.find("meta", attrs={"name": "description"})
    generator   = soup.find("meta", attrs={"name": "generator"})
    robots_meta = soup.find("meta", attrs={"name": "robots"})

    print(f"\n  {C.bold('Meta Info')}")
    divider()
    print(f"    {'Title':<18} {C.cyan(title.text.strip() if title else '—')}")
    desc_val = description['content'] if description else '—'
    if len(desc_val) > 80: desc_val = desc_val[:77] + "..."
    print(f"    {'Description':<18} {desc_val}")
    print(f"    {'Generator':<18} {C.yellow(generator['content']) if generator else '—'}")
    print(f"    {'Robots':<18} {robots_meta['content'] if robots_meta else '—'}")

    # Forms
    forms       = soup.find_all("form")
    csrf_tokens = [f for f in forms if f.find("input", attrs={"name": re.compile(r"csrf|token|_token", re.I)})]
    login_forms = [f for f in forms if f.find("input", attrs={"type": "password"})]

    print(f"\n  {C.bold(f'Forms ({len(forms)} found)')}")
    divider()
    if forms:
        print(f"    Total         {len(forms)}")
        csrf_str = C.green(f"✅ {len(csrf_tokens)}") if csrf_tokens else C.red("❌ 0  ← vulnerable!")
        print(f"    With CSRF     {csrf_str}")
        print(f"    Login Forms   {len(login_forms)}")

        for i, form in enumerate(forms, 1):
            action  = form.get("action", "—")
            method  = form.get("method", "GET").upper()
            inputs  = form.find_all("input")
            has_csrf = bool(form.find("input", attrs={"name": re.compile(r"csrf|token|_token", re.I)}))
            print(f"\n    {C.bold(f'Form #{i}')}")
            print(f"      {'Action':<12} {action}")
            print(f"      {'Method':<12} {method}")
            print(f"      {'Inputs':<12} {len(inputs)}")
            print(f"      {'CSRF':<12} {C.green('✅ Yes') if has_csrf else C.red('🔴 No')}")
    else:
        print(f"    {C.DIM}No forms found{C.RESET}")

    # Links
    all_links      = soup.find_all("a", href=True)
    internal_links = [a for a in all_links if a["href"].startswith("/") or base in a["href"]]
    external_links = [a for a in all_links if a["href"].startswith("http") and base not in a["href"]]

    print(f"\n  {C.bold('Links')}")
    divider()
    print(f"    Total      {len(all_links)}")
    print(f"    Internal   {len(internal_links)}")
    print(f"    External   {C.yellow(str(len(external_links))) if external_links else str(len(external_links))}")
    if external_links:
        print(f"\n  {C.DIM}External links (first 5):{C.RESET}")
        for a in external_links[:5]:
            print(f"    {C.GRAY}•{C.RESET} {a['href'][:80]}")

    # Static files
    js_files    = soup.find_all("script", src=True)
    css_files   = soup.find_all("link",   rel="stylesheet")
    external_js = [s for s in js_files if s["src"].startswith("http") and base not in s["src"]]

    print(f"\n  {C.bold('Static Files')}")
    divider()
    print(f"    JavaScript  {len(js_files)} files")
    print(f"    CSS         {len(css_files)} files")
    if external_js:
        print(f"\n  {C.yellow(f'⚠  External JS ({len(external_js)}) — potential supply chain risk:')}")
        for s in external_js[:5]:
            print(f"    {C.GRAY}•{C.RESET} {s['src'][:80]}")

    # Emails & phones
    text   = soup.get_text()
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)))
    phones = list(set(re.findall(r"(\+?\d[\d\s\-().]{7,}\d)", text)))

    print(f"\n  {C.bold('Emails & Phones')}")
    divider()
    if emails:
        print(f"  {C.yellow(f'Emails ({len(emails)}):')}")
        for e in emails[:5]:
            print(f"    {C.GRAY}•{C.RESET} {C.yellow(e)}")
    else:
        print(f"    {C.DIM}No emails found{C.RESET}")

    if phones:
        print(f"  {C.dim(f'Phones ({len(phones)}):')}")
        for p in phones[:3]:
            print(f"    {C.GRAY}•{C.RESET} {p.strip()}")
    else:
        print(f"    {C.DIM}No phones found{C.RESET}")

    # HTML comments
    import bs4
    comments = soup.find_all(string=lambda t: isinstance(t, bs4.Comment))
    sensitive_pat = re.compile(r"password|secret|key|token|api|todo|fixme|hack|bug", re.I)
    risky_comments = [c for c in comments if sensitive_pat.search(c.strip())]

    print(f"\n  {C.bold(f'HTML Comments ({len(comments)} total)')}")
    divider()
    if risky_comments:
        print(f"  {C.red(f'⚠  {len(risky_comments)} sensitive comment(s) detected!')}")
        for c in risky_comments:
            print(f"    {C.yellow(c.strip()[:100])}")
    elif comments:
        print(f"    {C.DIM}{len(comments)} non-sensitive comments{C.RESET}")
    else:
        print(f"    {C.DIM}No comments found{C.RESET}")

    # iframes
    iframes = soup.find_all("iframe")
    if iframes:
        print(f"\n  {C.bold(f'iFrames ({len(iframes)})')}")
        divider()
        for iframe in iframes:
            print(f"    {C.GRAY}•{C.RESET} {iframe.get('src','—')[:80]}")

    # Body summary
    print(f"\n  {C.bold('Body Summary')}")
    divider()
    print(f"    Size          {size_kb:.1f} KB")
    print(f"    Forms         {len(forms)}  {'(' + C.red('CSRF missing') + ')' if forms and not csrf_tokens else ''}")
    print(f"    External Links {len(external_links)}")
    print(f"    External JS    {len(external_js)}  {'⚠️' if external_js else ''}")
    print(f"    Emails exposed {len(emails)}  {'⚠️' if emails else ''}")
    print(f"    HTML Comments  {len(comments)}  {'⚠️' if risky_comments else ''}")

    RESULTS["body"] = {
        "size_kb":       round(size_kb, 1),
        "forms":         len(forms),
        "csrf_missing":  forms and not csrf_tokens,
        "external_links": len(external_links),
        "external_js":   len(external_js),
        "emails":        emails[:5],
        "phones":        [p.strip() for p in phones[:3]],
        "comments":      len(comments),
        "risky_comments": len(risky_comments),
    }

# ══════════════════════════════════════════════════════════════
#  Raw Headers & Cookies
# ══════════════════════════════════════════════════════════════

def print_raw_headers(response):
    RELEVANT = [
        "Server","X-Powered-By","Via","X-Generator",
        "X-AspNet-Version","X-AspNetMvc-Version",
        "X-Django-Version","X-Laravel-Version",
        "X-Drupal-Cache","X-CF-Powered-By",
    ]
    found = {h: response.headers[h] for h in RELEVANT if h in response.headers}
    if found:
        for h, v in found.items():
            print(f"  {C.GRAY}│{C.RESET}  {C.BOLD}{h}{C.RESET}  {C.yellow(v)}")
    else:
        print(f"  {C.DIM}No fingerprinting headers found{C.RESET}")
    RESULTS["raw_headers"] = found


def print_cookies(response):
    if not response.cookies:
        print(f"  {C.DIM}No cookies found{C.RESET}")
        return

    print(f"\n  {'Name':<26} {'Secure':<8} {'HttpOnly':<10} {'SameSite':<12} Value")
    print(f"  {'─'*26} {'─'*8} {'─'*10} {'─'*12} {'─'*30}")
    cookie_data = []
    for cookie in response.cookies:
        secure   = C.green("✅") if cookie.secure else C.red("❌")
        httponly = C.green("✅") if cookie.has_nonstandard_attr("HttpOnly") else C.red("❌")
        samesite = cookie.get_nonstandard_attr("SameSite", C.dim("—"))
        value    = cookie.value[:30] + ("…" if len(cookie.value) > 30 else "")
        print(f"  {cookie.name[:25]:<26} {secure:<18} {httponly:<20} {samesite:<12} {C.DIM}{value}{C.RESET}")
        cookie_data.append({"name": cookie.name, "secure": cookie.secure, "samesite": samesite})
    RESULTS["cookies"] = cookie_data

# ══════════════════════════════════════════════════════════════
#  Argument Parser
# ══════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="WebRecon — Web Security Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py -u https://example.com
  python scanner.py -u https://example.com -o report.json
  python scanner.py -u https://example.com --threads 20 --no-color
  python scanner.py -u https://example.com --skip ssl dns
        """
    )
    parser.add_argument("-u", "--url",      required=True,           help="Target URL")
    parser.add_argument("-o", "--output",                            help="Save results to JSON file")
    parser.add_argument("-t", "--threads",  type=int, default=15,   help="Threads for path scan (default: 15)")
    parser.add_argument("--no-color",       action="store_true",     help="Disable colored output")
    parser.add_argument("--skip",           nargs="+",               help="Skip modules: wappalyzer ssl dns headers cookies body files robots csp",
                        metavar="MODULE",   default=[])
    parser.add_argument("--timeout",        type=int, default=10,    help="Request timeout in seconds (default: 10)")
    return parser.parse_args()

# ══════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════

def main():
    args = parse_args()

    if args.no_color:
        no_color()

    print_banner()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    skip = set(s.lower() for s in args.skip)

    start_time = time.time()

    # ── Initial request ──────────────────────────────────────────────
    info(f"Target  : {C.bold(url)}")
    info(f"Threads : {args.threads}")
    info(f"Timeout : {args.timeout}s")
    if skip:
        info(f"Skipping: {C.yellow(', '.join(skip))}")
    print()

    try:
        response = requests.get(url, timeout=args.timeout, allow_redirects=True, headers=HEADERS)
    except requests.exceptions.ConnectionError:
        error("Connection failed — host unreachable")
        sys.exit(1)
    except requests.exceptions.Timeout:
        error(f"Request timed out after {args.timeout}s")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        error(f"Request error: {e}")
        sys.exit(1)

    elapsed_ms = round(response.elapsed.total_seconds() * 1000)
    status = response.status_code
    status_colored = (
        C.green(str(status))  if status < 300 else
        C.blue(str(status))   if status < 400 else
        C.yellow(str(status)) if status < 500 else
        C.red(str(status))
    )

    print(f"\n{C.BOLD}{C.BLUE}  ╔{'═'*54}╗{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  ║{C.RESET}  🎯  {C.bold('TARGET  ')} {C.cyan(url[:48]):<58}{C.BOLD}{C.BLUE}║{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  ║{C.RESET}  📡  {C.bold('STATUS  ')} {status_colored}   "
          f"  ⏱  {C.bold('RESPONSE')} {elapsed_ms} ms{' '*18}{C.BOLD}{C.BLUE}║{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  ╚{'═'*54}╝{C.RESET}")

    RESULTS["meta"] = {"url": url, "status": status, "response_ms": elapsed_ms}

    # ── Modules ──────────────────────────────────────────────────────

    if "wappalyzer" not in skip:
        section("Technology Detection", "🔍")
        techs, cats = load_wappalyzer_db()
        detected    = wappalyzer_detect(response, techs, cats)
        print_wappalyzer_results(detected)

    if "csp" not in skip:
        section("CSP & CORS Analysis", "🛡️")
        analyze_csp_cors(response, url)

    if "headers" not in skip:
        section("Security Headers", "🔒")
        check_security_headers(response.headers)

    if "fingerprint" not in skip:
        section("Server Fingerprint", "🖥️")
        print_raw_headers(response)

    if "cookies" not in skip:
        section("Cookies", "🍪")
        print_cookies(response)

    if "body" not in skip:
        section("Body Analysis", "📄")
        analyze_body(response, url)

    if "files" not in skip:
        section("Sensitive File Scanner", "🗂️")
        scan_sensitive_files(url, max_workers=args.threads)

    if "robots" not in skip:
        section("Robots.txt Analysis", "🤖")
        parse_robots(url)

    if "ssl" not in skip:
        section("SSL/TLS Analysis", "🔐")
        analyze_ssl(url)

    if "dns" not in skip:
        section("DNS Lookup", "🌐")
        dns_lookup(url)

    # ── Final Summary ────────────────────────────────────────────────
    total_time = round(time.time() - start_time, 2)

    section("Scan Complete", "✅")

    findings = RESULTS.get("sensitive_files", [])
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    missing_headers = RESULTS.get("security_headers", {}).get("missing", [])
    csp_issues = len(RESULTS.get("csp_cors", {}).get("csp", {}).get("issues", []))
    cors_issues = len(RESULTS.get("csp_cors", {}).get("cors", {}).get("issues", []))

    print(f"\n  {C.bold('Findings Summary')}\n")
    print(f"    {'Sensitive Files (CRITICAL)':<32} {C.critical(str(critical)) if critical else C.green('0')}")
    print(f"    {'Sensitive Files (HIGH)':<32} {C.red(str(high)) if high else C.green('0')}")
    print(f"    {'Missing Security Headers':<32} {C.yellow(str(len(missing_headers))) if missing_headers else C.green('0')}")
    print(f"    {'CSP Issues':<32} {C.yellow(str(csp_issues)) if csp_issues else C.green('0')}")
    print(f"    {'CORS Issues':<32} {C.yellow(str(cors_issues)) if cors_issues else C.green('0')}")
    print(f"\n    {C.DIM}Scan Duration: {total_time}s{C.RESET}")

    if args.output:
        RESULTS["scan_duration_s"] = total_time
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(RESULTS, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n  {C.green('[✓]')}  Results saved to {C.bold(args.output)}")

    print(f"\n{C.GRAY}{'═'*60}{C.RESET}\n")

if __name__ == "__main__":
    main()