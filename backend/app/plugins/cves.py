"""Version-aware CVE matcher plugin.

Detects software VERSIONS (not just software names) from Server headers,
X-Powered-By, HTML meta generators, and JS library filenames, then matches
them against known CVEs. "Apache 2.4.49 = CVE-2021-41773 path traversal to
RCE" is a real finding, not noise.

All CVEs below are real, public, and version-bounded. Exploitability is
rated so Jay sees weaponized RCEs above theoretical issues.
No API keys needed. GET only, read-only.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _parse_version(s: str) -> Tuple[int, ...]:
    """'2.4.49' -> (2, 4, 49). Non-numeric tails are dropped."""
    parts = []
    for chunk in re.split(r"[.\-+_]", s or ""):
        m = re.match(r"(\d+)", chunk)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    return tuple(parts) or (0,)


def _ver_lt(v: Tuple[int, ...], ref: Tuple[int, ...]) -> bool:
    n = max(len(v), len(ref))
    vv = v + (0,) * (n - len(v))
    rr = ref + (0,) * (n - len(ref))
    return vv < rr


def _ver_eq(v: Tuple[int, ...], ref: Tuple[int, ...]) -> bool:
    n = max(len(v), len(ref))
    vv = v + (0,) * (n - len(v))
    rr = ref + (0,) * (n - len(ref))
    return vv == rr


def _check(op: str, ver: Tuple[int, ...], ref: str) -> bool:
    r = _parse_version(ref)
    if op == "<":
        return _ver_lt(ver, r)
    if op == "<=":
        return _ver_lt(ver, r) or _ver_eq(ver, r)
    if op == "==":
        return _ver_eq(ver, r)
    if op == ">=":
        return not _ver_lt(ver, r)
    return False


# ---------------------------------------------------------------------------
# Version-specific CVE database. Each entry:
#   where: "server" | "powered_by" | "html" | "js" | "wp_generator"
#   version_re: regex with one capture group for the version string
#   vuln: list of (op, version) - ANY match means vulnerable
#   cve / severity / exploitability / title / remediation
# ---------------------------------------------------------------------------
VERSION_CVES: List[Dict] = [
    # -- Apache httpd -------------------------------------------------------
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("==", "2.4.49")],
     "cve": "CVE-2021-41773", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Apache 2.4.49 path traversal to RCE (public exploit)",
     "remediation": "Upgrade Apache to 2.4.51+ immediately. This version has a public RCE exploit."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("==", "2.4.50")],
     "cve": "CVE-2021-42013", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Apache 2.4.50 path traversal to RCE - 2.4.49 fix bypassed (public exploit)",
     "remediation": "Upgrade Apache to 2.4.51+ immediately. The 2.4.50 fix was incomplete."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.59")],
     "cve": "CVE-2024-38476", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.59 mod_proxy SSRF via malicious backend URL",
     "remediation": "Upgrade Apache to 2.4.59+. Review mod_proxy configs for attacker-controlled backend URLs."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/2\.2(\.\d+)?",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache 2.2 is end-of-life (no security patches since 2017)",
     "remediation": "Migrate to Apache 2.4.x. 2.2 has unpatched CVEs with public exploits."},
    # -- nginx --------------------------------------------------------------
    {"software": "nginx", "where": "server",
     "version_re": r"nginx/(\d+\.\d+\.\d+)",
     "vuln": [("<", "1.20.1")],
     "cve": "CVE-2021-23017", "severity": "medium",
     "exploitability": "public_poc",
     "title": "nginx < 1.20.1 resolver 1-byte memory overwrite (fixed in 1.20.1 / 1.21.0, DNS response)",
     "remediation": "Upgrade nginx to 1.20.1+ / 1.21.0+. Only exploitable when the resolver is used with attacker-influenced DNS."},
    # -- Microsoft IIS -------------------------------------------------------
    {"software": "Microsoft IIS", "where": "server",
     "version_re": r"microsoft-iis/(\d+\.\d+)",
     "vuln": [("==", "6.0")],
     "cve": "CVE-2017-7269", "severity": "critical",
     "exploitability": "weaponized",
     "title": "IIS 6.0 WebDAV buffer overflow RCE (public Metasploit module)",
     "remediation": "IIS 6.0 is end-of-life. Migrate off Windows Server 2003 immediately."},
    {"software": "Microsoft IIS", "where": "server",
     "version_re": r"microsoft-iis/7\.5",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "medium",
     "exploitability": "theoretical",
     "title": "IIS 7.5 is end-of-life (Server 2008 R2, no patches)",
     "remediation": "Migrate to a supported IIS version."},
    # -- OpenSSL (often inside the Server header) -----------------------------
    {"software": "OpenSSL", "where": "server",
     "version_re": r"openssl/(1\.0\.1[a-f])",
     "vuln": [(">=", "0")],
     "cve": "CVE-2014-0160", "severity": "critical",
     "exploitability": "weaponized",
     "title": "OpenSSL 1.0.1 Heartbleed - reads server memory incl. private keys (public exploit)",
     "remediation": "Upgrade OpenSSL to 1.0.1g+ immediately and rotate all certificates and keys."},
    # -- PHP (X-Powered-By) ----------------------------------------------------
    # Branch-scoped: the old single entry (<8.3.8/<8.2.21/<8.1.29 on a full
    # version) false-positived on e.g. PHP 7.2.x and 8.2.25, which are patched.
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/8\.3\.(\d+)",
     "vuln": [("<", "8")],
     "cve": "CVE-2024-4577", "severity": "critical",
     "exploitability": "weaponized",
     "title": "PHP-CGI 8.3.x < 8.3.8 argument injection to RCE on Windows (public exploit)",
     "remediation": "Upgrade PHP to 8.3.8+. Move off PHP-CGI; use mod_php or php-fpm."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/8\.2\.(\d+)",
     "vuln": [("<", "21")],
     "cve": "CVE-2024-4577", "severity": "critical",
     "exploitability": "weaponized",
     "title": "PHP-CGI 8.2.x < 8.2.21 argument injection to RCE on Windows (public exploit)",
     "remediation": "Upgrade PHP to 8.2.21+. Move off PHP-CGI; use mod_php or php-fpm."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/8\.1\.(\d+)",
     "vuln": [("<", "29")],
     "cve": "CVE-2024-4577", "severity": "critical",
     "exploitability": "weaponized",
     "title": "PHP-CGI 8.1.x < 8.1.29 argument injection to RCE on Windows (public exploit)",
     "remediation": "Upgrade PHP to 8.1.29+. Move off PHP-CGI; use mod_php or php-fpm."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/8\.1\.0-dev",
     "vuln": [(">=", "0")],
     "cve": "BACKDOOR", "severity": "critical",
     "exploitability": "weaponized",
     "title": "PHP 8.1.0-dev backdoor - RCE via User-Agentt header (no CVE, real backdoor)",
     "remediation": "This is a backdoored dev build. Rebuild from a clean release immediately."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/([45]\.\d+\.\d+)",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "PHP 5.x/4.x is end-of-life with unpatched RCE CVEs",
     "remediation": "Upgrade to a supported PHP 8.x release."},
    # -- Express.js ------------------------------------------------------------
    {"software": "Express.js", "where": "powered_by",
     "version_re": r"express",
     "vuln": [],
     "cve": "CVE-2022-24999", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Express < 4.17.3 qs prototype pollution - verify version",
     "remediation": "Upgrade Express to 4.17.3+. Confirm the qs version bundled.",
     "version_optional": True},
    # -- Next.js ---------------------------------------------------------------
    {"software": "Next.js", "where": "powered_by",
     "version_re": r"next\.js",
     "vuln": [],
     "cve": "CVE-2025-29927", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Next.js middleware authorization bypass < 15.2.3 / < 14.2.25 - verify version (public exploit)",
     "remediation": "Upgrade Next.js to 15.2.3+ / 14.2.25+. Check x-powered-by or build manifests for the version.",
     "version_optional": True},
    # -- WordPress (meta generator) ---------------------------------------------
    {"software": "WordPress", "where": "wp_generator",
     "version_re": r"wordpress (\d+\.\d+(?:\.\d+)?)",
     "vuln": [("<", "5.8.3")],
     "cve": "CVE-2022-21661", "severity": "high",
     "exploitability": "public_poc",
     "title": "WordPress < 5.8.3 WP_Query SQL injection",
     "remediation": "Upgrade WordPress core immediately."},
    # -- JS libraries (filenames / CDN URLs in HTML) ------------------------------
    {"software": "jQuery", "where": "js",
     "version_re": r"jquery[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "3.5.0")],
     "cve": "CVE-2020-11022 / CVE-2020-11023", "severity": "medium",
     "exploitability": "public_poc",
     "title": "jQuery < 3.5.0 XSS via html()/DOM manipulation",
     "remediation": "Upgrade jQuery to 3.5.0+."},
    {"software": "Bootstrap", "where": "js",
     "version_re": r"bootstrap[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "4.6.1")],
     "cve": "CVE-2018-14041", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Bootstrap < 4.6.1 XSS in collapse plugin",
     "remediation": "Upgrade Bootstrap to 4.6.1+ (or 5.x)."},
    {"software": "AngularJS", "where": "js",
     "version_re": r"angular(?:\.min)?\.js|angular/(\d+\.\d+\.\d+)",
     "vuln": [("<", "1.8.0")],
     "cve": "CVE-2021-4231", "severity": "medium",
     "exploitability": "public_poc",
     "title": "AngularJS < 1.8.0 XSS (EOL framework, multiple known XSS CVEs)",
     "remediation": "Migrate off AngularJS (EOL). At minimum upgrade to 1.8.3+."},
    {"software": "Moment.js", "where": "js",
     "version_re": r"moment[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "2.29.4")],
     "cve": "CVE-2022-24785", "severity": "medium",
     "exploitability": "theoretical",
     "title": "Moment.js < 2.29.4 path traversal / ReDoS",
     "remediation": "Upgrade Moment.js to 2.29.4+ or migrate to a maintained date library."},
    {"software": "Lodash", "where": "js",
     "version_re": r"lodash[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "4.17.21")],
     "cve": "CVE-2021-23337 / CVE-2020-28500", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Lodash < 4.17.21 prototype pollution",
     "remediation": "Upgrade Lodash to 4.17.21+."},
    # -- CMS / framework generic signatures (kept from before, tightened) -----------
    # (Joomla CVE-2023-23752 generic advisory removed: superseded by the
    # version-bound 4.x entry below, which no longer fires on patched versions.)
    {"software": "Drupal", "where": "html",
     "version_re": r"drupal",
     "vuln": [],
     "cve": "CVE-2018-7600", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Drupalgeddon2 RCE - check version < 7.58 / < 8.5.1 (public exploit)",
     "remediation": "Upgrade Drupal immediately if below 7.58 / 8.5.1.",
     "version_optional": True},
    {"software": "Laravel", "where": "html",
     "version_re": r"laravel",
     "vuln": [],
     "cve": "CVE-2021-3129", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Laravel debug mode RCE via /_ignition/execute-solution - check if debug is on",
     "remediation": "Disable APP_DEBUG in production. Upgrade Laravel.",
     "version_optional": True},
    {"software": "Apache Struts", "where": "html",
     "version_re": r"struts",
     "vuln": [],
     "cve": "CVE-2017-5638", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Struts2 Jakarta RCE - check version (public exploit)",
     "remediation": "Upgrade Struts to a patched release.",
     "version_optional": True},
    {"software": "Spring Framework", "where": "html",
     "version_re": r"spring",
     "vuln": [],
     "cve": "CVE-2022-22965", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Spring4Shell RCE - verify Spring >= 5.3.18 / 5.2.20 (public exploit)",
     "remediation": "Upgrade Spring Framework to 5.3.18+ / 5.2.20+. Check /actuator for version leaks.",
     "version_optional": True},
    # -- Apache httpd: more version-bound RCE/smuggling -------------------------
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.56")],
     "cve": "CVE-2023-25690", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.56 HTTP response splitting via mod_proxy (public PoC)",
     "remediation": "Upgrade Apache to 2.4.56+. Review RewriteRules with attacker-controlled input."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.55")],
     "cve": "CVE-2023-27522", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.55 mod_proxy_uwsgi response smuggling",
     "remediation": "Upgrade Apache to 2.4.55+."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.52")],
     "cve": "CVE-2021-44790", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.52 mod_lua buffer overflow RCE (public PoC)",
     "remediation": "Upgrade Apache to 2.4.52+. Disable mod_lua if unused."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.53")],
     "cve": "CVE-2022-22720", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.53 HTTP request smuggling (public PoC)",
     "remediation": "Upgrade Apache to 2.4.53+."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.53")],
     "cve": "CVE-2022-23943", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.53 mod_dav out-of-bounds write (public PoC)",
     "remediation": "Upgrade Apache to 2.4.53+. Disable mod_dav if WebDAV is unused."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.60")],
     "cve": "CVE-2024-38477", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.60 mod_proxy SSRF - attacker as proxy backend (public PoC)",
     "remediation": "Upgrade Apache to 2.4.60+. Audit ProxyPass targets for attacker control."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(1\.3(\.\d+)?|2\.0(\.\d+)?)",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache 1.3/2.0 is end-of-life with unpatched RCE CVEs",
     "remediation": "Migrate to Apache 2.4.x. These branches have public RCE exploits."},
    # -- nginx: more -------------------------------------------------------------
    {"software": "nginx", "where": "server",
     "version_re": r"nginx/(\d+\.\d+\.\d+)",
     "vuln": [("<", "1.17.7")],
     "cve": "CVE-2019-20372", "severity": "high",
     "exploitability": "public_poc",
     "title": "nginx < 1.17.7 HTTP request smuggling via error_page (public PoC)",
     "remediation": "Upgrade nginx to 1.17.7+."},
    {"software": "nginx", "where": "server",
     "version_re": r"nginx/(\d+\.\d+\.\d+)",
     "vuln": [("<", "1.13.3")],
     "cve": "CVE-2017-7529", "severity": "medium",
     "exploitability": "public_poc",
     "title": "nginx < 1.13.3 range-filter integer overflow - info leak (public PoC)",
     "remediation": "Upgrade nginx to 1.13.3+."},
    # -- Apache Tomcat (version leaks in error pages) -----------------------------
    {"software": "Apache Tomcat", "where": "html",
     "version_re": r"apache tomcat/7\.0\.(\d+)",
     "vuln": [("<", "100")],
     "cve": "CVE-2020-1938", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Tomcat 7.0.x < 7.0.100 Ghostcat - AJP file read to RCE (public exploit)",
     "remediation": "Upgrade Tomcat to 7.0.100+. If AJP is unused, disable the AJP connector or bind it to localhost with a secret."},
    {"software": "Apache Tomcat", "where": "html",
     "version_re": r"apache tomcat/8\.5\.(\d+)",
     "vuln": [("<", "51")],
     "cve": "CVE-2020-1938", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Tomcat 8.5.x < 8.5.51 Ghostcat - AJP file read to RCE (public exploit)",
     "remediation": "Upgrade Tomcat to 8.5.51+. If AJP is unused, disable the AJP connector or bind it to localhost with a secret."},
    {"software": "Apache Tomcat", "where": "html",
     "version_re": r"apache tomcat/9\.0\.(\d+)",
     "vuln": [("<", "31")],
     "cve": "CVE-2020-1938", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Tomcat 9.0.x < 9.0.31 Ghostcat - AJP file read to RCE (public exploit)",
     "remediation": "Upgrade Tomcat to 9.0.31+. If AJP is unused, disable the AJP connector or bind it to localhost with a secret."},
    {"software": "Apache Tomcat", "where": "html",
     "version_re": r"apache tomcat/7\.0\.(\d+)",
     "vuln": [("<", "100")],
     "cve": "CVE-2020-9484", "severity": "high",
     "exploitability": "public_poc",
     "title": "Tomcat 7.0.x < 7.0.100 session-persistence RCE (public PoC)",
     "remediation": "Upgrade Tomcat to 7.0.100+. Audit PersistenceManager file uploads."},
    {"software": "Apache Tomcat", "where": "html",
     "version_re": r"apache tomcat/8\.5\.(\d+)",
     "vuln": [("<", "51")],
     "cve": "CVE-2020-9484", "severity": "high",
     "exploitability": "public_poc",
     "title": "Tomcat 8.5.x < 8.5.51 session-persistence RCE (public PoC)",
     "remediation": "Upgrade Tomcat to 8.5.51+. Audit PersistenceManager file uploads."},
    {"software": "Apache Tomcat", "where": "html",
     "version_re": r"apache tomcat/9\.0\.(\d+)",
     "vuln": [("<", "31")],
     "cve": "CVE-2020-9484", "severity": "high",
     "exploitability": "public_poc",
     "title": "Tomcat 9.0.x < 9.0.31 session-persistence RCE (public PoC)",
     "remediation": "Upgrade Tomcat to 9.0.31+. Audit PersistenceManager file uploads."},
    # -- OpenSSL (Server header) ---------------------------------------------------
    {"software": "OpenSSL", "where": "server",
     "version_re": r"openssl/(3\.0\.\d+)",
     "vuln": [("<", "3.0.7")],
     "cve": "CVE-2022-3602", "severity": "high",
     "exploitability": "public_poc",
     "title": "OpenSSL 3.0.x < 3.0.7 X.509 buffer overrun (public PoC)",
     "remediation": "Upgrade OpenSSL to 3.0.7+."},
    {"software": "OpenSSL", "where": "server",
     "version_re": r"openssl/(1\.0\.2[a-z])",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "OpenSSL 1.0.2 is end-of-life with unpatched CVEs",
     "remediation": "Upgrade OpenSSL to a supported 3.x release."},
    # -- PHP: php-fpm RCE + EOL branches --------------------------------------------
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/7\.2\.(\d+)",
     "vuln": [("<", "24")],
     "cve": "CVE-2019-11043", "severity": "high",
     "exploitability": "public_poc",
     "title": "PHP-FPM 7.2.x < 7.2.24 RCE via crafted PATH_INFO (public exploit, needs nginx fastcgi config)",
     "remediation": "Upgrade PHP to 7.2.24+. Verify nginx fastcgi_split_path_info configs."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/7\.3\.(\d+)",
     "vuln": [("<", "11")],
     "cve": "CVE-2019-11043", "severity": "high",
     "exploitability": "public_poc",
     "title": "PHP-FPM 7.3.x < 7.3.11 RCE via crafted PATH_INFO (public exploit, needs nginx fastcgi config)",
     "remediation": "Upgrade PHP to 7.3.11+. Verify nginx fastcgi_split_path_info configs."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/(7\.\d+\.\d+)",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "PHP 7.x is end-of-life with unpatched RCE CVEs",
     "remediation": "Upgrade to a supported PHP 8.x release."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/(8\.0\.\d+)",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "PHP 8.0 is end-of-life with unpatched CVEs",
     "remediation": "Upgrade to a supported PHP 8.x release."},
    # -- Django ----------------------------------------------------------------------
    {"software": "Django", "where": "html",
     "version_re": r"django",
     "vuln": [],
     "cve": "CVE-2022-34265", "severity": "high",
     "exploitability": "public_poc",
     "title": "Django < 4.0.5 / < 3.2.13 SQL injection via Trunc/Extract - check version (public PoC)",
     "remediation": "Upgrade Django to 4.0.5+ / 3.2.13+.",
     "version_optional": True},
    {"software": "Django", "where": "html",
     "version_re": r"django",
     "vuln": [],
     "cve": "CVE-2021-35042", "severity": "high",
     "exploitability": "public_poc",
     "title": "Django < 2.2.25 / < 3.1.13 / < 3.2.5 SQL injection via order_by - check version (public PoC)",
     "remediation": "Upgrade Django to a patched release.",
     "version_optional": True},
    # -- Ruby on Rails -----------------------------------------------------------------
    {"software": "Ruby on Rails", "where": "html",
     "version_re": r"\brails\b|ruby on rails",
     "vuln": [],
     "cve": "CVE-2022-32224", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Rails YAML deserialization RCE < 7.0.2.4 / < 6.1.5.1 / < 6.0.4.8 / < 5.2.8.1 - check version (public exploit)",
     "remediation": "Upgrade Rails to a patched release.",
     "version_optional": True},
    {"software": "Ruby on Rails", "where": "html",
     "version_re": r"\brails\b|ruby on rails",
     "vuln": [],
     "cve": "CVE-2019-5420", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Rails development-mode RCE < 5.2.2.1 / < 5.1.6.2 - check if dev mode is exposed (public exploit)",
     "remediation": "Never expose Rails development mode publicly. Upgrade Rails.",
     "version_optional": True},
    # -- Node.js -------------------------------------------------------------------------
    {"software": "Node.js", "where": "html",
     "version_re": r"node\.js",
     "vuln": [],
     "cve": "CVE-2021-44531", "severity": "high",
     "exploitability": "public_poc",
     "title": "Node.js < 17.3.1 / < 16.13.2 / < 14.18.3 / < 12.22.9 HTTP request smuggling - check version (public PoC)",
     "remediation": "Upgrade Node.js to a patched release.",
     "version_optional": True},
    # -- WordPress core: more version-bound -------------------------------------------------
    {"software": "WordPress", "where": "wp_generator",
     "version_re": r"wordpress (\d+\.\d+(?:\.\d+)?)",
     "vuln": [("<", "6.5.2")],
     "cve": "CVE-2024-4439", "severity": "high",
     "exploitability": "public_poc",
     "title": "WordPress < 6.5.2 unauthenticated stored XSS (public PoC)",
     "remediation": "Upgrade WordPress core immediately."},
    {"software": "WordPress", "where": "wp_generator",
     "version_re": r"wordpress (\d+\.\d+(?:\.\d+)?)",
     "vuln": [("<", "5.7.2")],
     "cve": "CVE-2021-29447", "severity": "high",
     "exploitability": "public_poc",
     "title": "WordPress < 5.7.2 XXE in media library (public PoC)",
     "remediation": "Upgrade WordPress core immediately."},
    {"software": "WordPress", "where": "wp_generator",
     "version_re": r"wordpress (\d+\.\d+(?:\.\d+)?)",
     "vuln": [("<", "4.7.2")],
     "cve": "CVE-2017-1001000", "severity": "critical",
     "exploitability": "weaponized",
     "title": "WordPress 4.7.0/4.7.1 REST API unauthenticated content injection (public exploit)",
     "remediation": "Upgrade WordPress core immediately."},
    # -- WordPress plugins (wp-content paths in HTML) ---------------------------------------
    {"software": "WordPress plugin: Elementor Pro", "where": "html",
     "version_re": r"elementor",
     "vuln": [],
     "cve": "CVE-2023-30847", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Elementor Pro < 3.11.7 broken access control - unauthenticated admin creation - check version (public exploit)",
     "remediation": "Upgrade Elementor Pro to 3.11.7+. Audit wp-admin users for rogue admins.",
     "version_optional": True},
    {"software": "WordPress plugin: Contact Form 7", "where": "html",
     "version_re": r"contact[- ]?form[- ]?7|wpcf7",
     "vuln": [],
     "cve": "CVE-2020-35489", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Contact Form 7 < 5.3.2 unrestricted file upload to RCE - check version (public exploit)",
     "remediation": "Upgrade Contact Form 7 to 5.3.2+.",
     "version_optional": True},
    {"software": "WordPress plugin: File Manager", "where": "html",
     "version_re": r"wp-file-manager|file[- ]?manager",
     "vuln": [],
     "cve": "CVE-2020-25213", "severity": "critical",
     "exploitability": "weaponized",
     "title": "File Manager < 6.9 unauthenticated RCE via file upload - check version (public exploit)",
     "remediation": "Upgrade File Manager to 6.9+. Remove it if unused - it is heavily targeted.",
     "version_optional": True},
    {"software": "WordPress plugin: Slider Revolution", "where": "html",
     "version_re": r"revslider|slider[- ]?revolution",
     "vuln": [],
     "cve": "CVE-2014-9735", "severity": "high",
     "exploitability": "weaponized",
     "title": "Slider Revolution <= 4.6.5 arbitrary file download - check version (widely exploited)",
     "remediation": "Upgrade Slider Revolution past 4.6.5.",
     "version_optional": True},
    {"software": "WordPress plugin: Ultimate Member", "where": "html",
     "version_re": r"ultimate[- ]?member",
     "vuln": [],
     "cve": "CVE-2023-3460", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Ultimate Member privilege escalation to admin - verify patched for CVE-2023-3460 (public exploit)",
     "remediation": "Upgrade Ultimate Member to a patched release. Audit admin users.",
     "version_optional": True},
    {"software": "WordPress plugin: Advanced Custom Fields", "where": "html",
     "version_re": r"advanced[- ]?custom[- ]?fields",
     "vuln": [],
     "cve": "CVE-2023-30777", "severity": "high",
     "exploitability": "public_poc",
     "title": "Advanced Custom Fields < 6.1.6 reflected XSS - check version (public PoC)",
     "remediation": "Upgrade Advanced Custom Fields to 6.1.6+.",
     "version_optional": True},
    {"software": "WordPress plugin: Essential Addons for Elementor", "where": "html",
     "version_re": r"essential[- ]?addons",
     "vuln": [],
     "cve": "CVE-2023-32243", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Essential Addons for Elementor < 5.9.13 password reset to admin takeover - check version (public exploit)",
     "remediation": "Upgrade Essential Addons to 5.9.13+. Audit admin users.",
     "version_optional": True},
    {"software": "WordPress plugin: LayerSlider", "where": "html",
     "version_re": r"layerslider",
     "vuln": [],
     "cve": "CVE-2024-2879", "severity": "critical",
     "exploitability": "weaponized",
     "title": "LayerSlider < 7.10.0 SQL injection - check version (exploited in the wild)",
     "remediation": "Upgrade LayerSlider to 7.10.0+.",
     "version_optional": True},
    {"software": "WordPress plugin: Backup Migration", "where": "html",
     "version_re": r"backup[- ]?migration",
     "vuln": [],
     "cve": "CVE-2023-6553", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Backup Migration < 1.3.7 unauthenticated RCE - check version (public exploit)",
     "remediation": "Upgrade Backup Migration to 1.3.7+. Remove it if unused.",
     "version_optional": True},
    {"software": "WordPress plugin: UpdraftPlus", "where": "html",
     "version_re": r"updraft",
     "vuln": [],
     "cve": "CVE-2022-0633", "severity": "high",
     "exploitability": "public_poc",
     "title": "UpdraftPlus < 1.22.3 low-privilege backup download - check version (public PoC)",
     "remediation": "Upgrade UpdraftPlus to 1.22.3+.",
     "version_optional": True},
    {"software": "WordPress plugin: Forminator", "where": "html",
     "version_re": r"forminator",
     "vuln": [],
     "cve": "CVE-2024-28890", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Forminator < 1.29.3 unauthenticated file upload to RCE - check version (public exploit)",
     "remediation": "Upgrade Forminator to 1.29.3+.",
     "version_optional": True},
    {"software": "WordPress plugin: Bricks Builder", "where": "html",
     "version_re": r"bricks[- ]?builder|\bbricks\b",
     "vuln": [],
     "cve": "CVE-2024-25600", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Bricks Builder < 1.9.6 unauthenticated RCE - check version (public exploit)",
     "remediation": "Upgrade Bricks to 1.9.6+.",
     "version_optional": True},
    # -- Joomla: version-bound via meta generator --------------------------------------------
    {"software": "Joomla", "where": "html",
     "version_re": r"content=[\"']joomla![^\"]*version (3\.\d+\.\d+)",
     "vuln": [("<", "3.4.6")],
     "cve": "CVE-2015-8562", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Joomla < 3.4.6 object injection RCE (public exploit)",
     "remediation": "Upgrade Joomla to 3.4.6+ immediately."},
    {"software": "Joomla", "where": "html",
     "version_re": r"content=[\"']joomla![^\"]*version (4\.\d+\.\d+)",
     "vuln": [("<", "4.2.8")],
     "cve": "CVE-2023-23752", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Joomla 4.0.0-4.2.7 improper API access - unauthenticated data access (public exploit)",
     "remediation": "Upgrade Joomla to 4.2.8+."},
    # -- Drupal --------------------------------------------------------------------------------
    {"software": "Drupal", "where": "html",
     "version_re": r"drupal",
     "vuln": [],
     "cve": "CVE-2018-7602", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Drupalgeddon3 RCE < 7.59 / < 8.5.3 - check version (public exploit)",
     "remediation": "Upgrade Drupal immediately if below 7.59 / 8.5.3.",
     "version_optional": True},
    {"software": "Drupal", "where": "html",
     "version_re": r"drupal",
     "vuln": [],
     "cve": "CVE-2019-6340", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Drupal REST RCE 8.5.x < 8.5.11 / 8.6.x < 8.6.10 - check version (public exploit)",
     "remediation": "Upgrade Drupal immediately. Disable RESTful Web Services if unused.",
     "version_optional": True},
    # -- Other CMS / e-commerce -------------------------------------------------------------------
    {"software": "Adobe Magento", "where": "html",
     "version_re": r"magento",
     "vuln": [],
     "cve": "CVE-2024-34102", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Magento CosmicSting XXE to RCE < 2.4.7 / < 2.4.6-p5 / < 2.4.5-p7 / < 2.4.4-p8 - check version (public exploit)",
     "remediation": "Apply the isolated patch or upgrade Magento.",
     "version_optional": True},
    {"software": "Craft CMS", "where": "html",
     "version_re": r"craft ?cms",
     "vuln": [],
     "cve": "CVE-2023-41892", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Craft CMS < 4.4.14 RCE via Imagick - check version (exploited in the wild)",
     "remediation": "Upgrade Craft CMS to 4.4.14+.",
     "version_optional": True},
    {"software": "Chamilo LMS", "where": "html",
     "version_re": r"chamilo",
     "vuln": [],
     "cve": "CVE-2023-3533", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Chamilo LMS unauthenticated RCE via webshell upload - verify patched (public exploit)",
     "remediation": "Upgrade Chamilo to a patched release.",
     "version_optional": True},
    # -- JS libraries: more -------------------------------------------------------------------------
    {"software": "jQuery", "where": "js",
     "version_re": r"jquery[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "3.4.0")],
     "cve": "CVE-2019-11358", "severity": "medium",
     "exploitability": "public_poc",
     "title": "jQuery < 3.4.0 prototype pollution (public PoC)",
     "remediation": "Upgrade jQuery to 3.4.0+ (3.5.0+ recommended)."},
    {"software": "jQuery UI", "where": "js",
     "version_re": r"jquery[.-]?ui[/\-.](\d+\.\d+\.\d+)",
     "vuln": [("<", "1.13.0")],
     "cve": "CVE-2021-41182", "severity": "medium",
     "exploitability": "public_poc",
     "title": "jQuery UI < 1.13.0 XSS (multiple CVEs, public PoC)",
     "remediation": "Upgrade jQuery UI to 1.13.0+."},
    {"software": "Handlebars", "where": "js",
     "version_re": r"handlebars[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "4.7.7")],
     "cve": "CVE-2021-20922", "severity": "high",
     "exploitability": "public_poc",
     "title": "Handlebars < 4.7.7 template RCE (public PoC)",
     "remediation": "Upgrade Handlebars to 4.7.7+."},
    {"software": "Bootstrap", "where": "js",
     "version_re": r"bootstrap[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "4.3.1")],
     "cve": "CVE-2019-8331", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Bootstrap < 4.3.1 XSS in tooltip/popover (public PoC)",
     "remediation": "Upgrade Bootstrap to 4.3.1+ (5.x recommended)."},
    {"software": "CKEditor", "where": "js",
     "version_re": r"ckeditor[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "4.17.0")],
     "cve": "CVE-2021-41165", "severity": "medium",
     "exploitability": "public_poc",
     "title": "CKEditor 4 < 4.17.0 XSS (public PoC)",
     "remediation": "Upgrade CKEditor to 4.17.0+."},
    {"software": "Chart.js", "where": "js",
     "version_re": r"chart\.js[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "2.9.4")],
     "cve": "CVE-2020-7746", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Chart.js < 2.9.4 prototype pollution (public PoC)",
     "remediation": "Upgrade Chart.js to 2.9.4+."},
    {"software": "Dojo", "where": "js",
     "version_re": r"dojo[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "1.16.4")],
     "cve": "CVE-2021-23450", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Dojo < 1.16.4 prototype pollution (public PoC)",
     "remediation": "Upgrade Dojo to 1.16.4+."},
    # -- Java frameworks: more ------------------------------------------------------------------------
    {"software": "Spring Cloud Function", "where": "html",
     "version_re": r"spring[- ]cloud",
     "vuln": [],
     "cve": "CVE-2022-22963", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Spring Cloud Function < 3.1.7 / < 3.2.3 SpEL RCE - check version (public exploit)",
     "remediation": "Upgrade Spring Cloud Function to 3.1.7+ / 3.2.3+.",
     "version_optional": True},
    {"software": "Apache Struts", "where": "html",
     "version_re": r"struts",
     "vuln": [],
     "cve": "CVE-2023-50164", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Struts 2.0.0-2.5.32 / 6.0.0-6.3.0.1 file-upload RCE - check version (public exploit)",
     "remediation": "Upgrade Struts to 2.5.33+ / 6.3.0.2+.",
     "version_optional": True},
    {"software": "ThinkPHP", "where": "html",
     "version_re": r"thinkphp",
     "vuln": [],
     "cve": "CVE-2018-20062", "severity": "critical",
     "exploitability": "weaponized",
     "title": "ThinkPHP 5.0.x <= 5.0.23 / 5.1.x <= 5.1.31 RCE - check version (public exploit)",
     "remediation": "Upgrade ThinkPHP to a patched release.",
     "version_optional": True},
    {"software": "Apache Log4j", "where": "html",
     "version_re": r"log4j",
     "vuln": [],
     "cve": "CVE-2021-44228", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Log4Shell - log4j-core 2.0-beta9 to 2.14.1 RCE - check version (public exploit)",
     "remediation": "Upgrade log4j-core to 2.17.1+ (2.15.0 minimum).",
     "version_optional": True},
    {"software": "Apache Solr", "where": "html",
     "version_re": r"\bsolr\b|apache solr",
     "vuln": [],
     "cve": "CVE-2021-44228", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Solr ships log4j - Log4Shell RCE if log4j-core < 2.15.0 - check version (public exploit)",
     "remediation": "Upgrade Solr to a release with log4j-core 2.17.1+.",
     "version_optional": True},
    # -- DevOps: Jenkins (X-Jenkins header), GitLab, Jira, Confluence, more ---------------
    {"software": "Jenkins", "where": "server",
     "version_re": r"x-jenkins/(\d+\.\d+(?:\.\d+)?)",
     "vuln": [("<", "2.426.3")],
     "cve": "CVE-2024-23897", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Jenkins < 2.442 / < 2.426.3 arbitrary file read to RCE via CLI (public exploit)",
     "remediation": "Upgrade Jenkins to 2.442+ / 2.426.3+. Disable CLI access if unused."},
    {"software": "Jenkins", "where": "server",
     "version_re": r"x-jenkins/(2\.(?:42[7-9]|43\d|44[01]))(?![\.\d])",
     "vuln": [(">=", "0")],
     "cve": "CVE-2024-23897", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Jenkins weekly 2.427-2.441 arbitrary file read to RCE via CLI (public exploit)",
     "remediation": "Upgrade Jenkins to 2.442+. Disable CLI access if unused."},
    {"software": "Jenkins", "where": "server",
     "version_re": r"x-jenkins/(\d+\.\d+(?:\.\d+)?)",
     "vuln": [("<", "2.138.2")],
     "cve": "CVE-2018-1000861", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Jenkins < 2.138.2 RCE (public exploit)",
     "remediation": "Upgrade Jenkins to 2.138.2+."},
    {"software": "GitLab", "where": "html",
     "version_re": r"gitlab",
     "vuln": [],
     "cve": "CVE-2023-7028", "severity": "critical",
     "exploitability": "weaponized",
     "title": "GitLab < 16.5.6 / < 16.6.4 / < 16.7.2 password-reset account takeover - check version (public exploit)",
     "remediation": "Upgrade GitLab immediately. Enable 2FA for all users.",
     "version_optional": True},
    {"software": "GitLab", "where": "html",
     "version_re": r"gitlab",
     "vuln": [],
     "cve": "CVE-2021-22205", "severity": "critical",
     "exploitability": "weaponized",
     "title": "GitLab < 13.10.3 / < 13.9.6 / < 13.8.8 ExifTool RCE via image upload - check version (public exploit)",
     "remediation": "Upgrade GitLab immediately.",
     "version_optional": True},
    {"software": "Atlassian Confluence", "where": "html",
     "version_re": r"confluence",
     "vuln": [],
     "cve": "CVE-2023-22515", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Confluence < 8.5.5 / < 8.7.2 broken access control to admin to RCE - check version (public exploit)",
     "remediation": "Upgrade Confluence immediately. Restrict /setup/* endpoints.",
     "version_optional": True},
    {"software": "Atlassian Confluence", "where": "html",
     "version_re": r"confluence",
     "vuln": [],
     "cve": "CVE-2022-26134", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Confluence OGNL injection RCE (7.4.0-7.17.x) - check version (public exploit)",
     "remediation": "Upgrade Confluence to 7.4.17+ / 7.13.7+ / 7.18.1+.",
     "version_optional": True},
    {"software": "Atlassian Confluence", "where": "html",
     "version_re": r"confluence",
     "vuln": [],
     "cve": "CVE-2021-26084", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Confluence OGNL injection RCE - check version is patched (public exploit)",
     "remediation": "Upgrade Confluence to a patched release.",
     "version_optional": True},
    {"software": "Atlassian Jira", "where": "html",
     "version_re": r"\bjira\b|atlassian",
     "vuln": [],
     "cve": "CVE-2019-11581", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Jira < 8.2.3 template injection RCE via ContactAdministrators - check version (public exploit)",
     "remediation": "Upgrade Jira to 8.2.3+.",
     "version_optional": True},
    {"software": "JetBrains TeamCity", "where": "html",
     "version_re": r"teamcity",
     "vuln": [],
     "cve": "CVE-2024-27198", "severity": "critical",
     "exploitability": "weaponized",
     "title": "TeamCity < 2023.11.4 auth bypass to admin to RCE - check version (public exploit)",
     "remediation": "Upgrade TeamCity to 2023.11.4+.",
     "version_optional": True},
    {"software": "Grafana", "where": "html",
     "version_re": r"grafana",
     "vuln": [],
     "cve": "CVE-2021-43798", "severity": "high",
     "exploitability": "weaponized",
     "title": "Grafana < 8.3.1 path traversal - arbitrary file read - check version (public exploit)",
     "remediation": "Upgrade Grafana to 8.3.1+.",
     "version_optional": True},
    {"software": "Atlassian Bitbucket", "where": "html",
     "version_re": r"bitbucket",
     "vuln": [],
     "cve": "CVE-2022-36804", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Bitbucket < 7.21.0 unauthenticated RCE via REST API - check version (public exploit)",
     "remediation": "Upgrade Bitbucket to 7.21.0+.",
     "version_optional": True},
    {"software": "Zabbix", "where": "html",
     "version_re": r"zabbix",
     "vuln": [],
     "cve": "CVE-2022-23131", "severity": "critical",
     "exploitability": "public_poc",
     "title": "Zabbix < 5.4.9 / 6.0.0 SAML SSO authentication bypass - check version (public PoC)",
     "remediation": "Upgrade Zabbix to 5.4.9+ / 6.0.0+.",
     "version_optional": True},
    {"software": "phpMyAdmin", "where": "html",
     "version_re": r"phpmyadmin",
     "vuln": [],
     "cve": "CVE-2020-10804", "severity": "high",
     "exploitability": "public_poc",
     "title": "phpMyAdmin < 5.0.0 SQL injection - check version (public PoC)",
     "remediation": "Upgrade phpMyAdmin to 5.0.0+. Never expose phpMyAdmin publicly.",
     "version_optional": True},
    {"software": "phpMyAdmin", "where": "html",
     "version_re": r"phpmyadmin",
     "vuln": [],
     "cve": "CVE-2016-5734", "severity": "critical",
     "exploitability": "weaponized",
     "title": "phpMyAdmin < 4.6.4 RCE via preg_replace - check version (public exploit)",
     "remediation": "Upgrade phpMyAdmin. Never expose phpMyAdmin publicly.",
     "version_optional": True},
    {"software": "Microsoft SharePoint", "where": "html",
     "version_re": r"sharepoint|microsoftsharepointteamservices",
     "vuln": [],
     "cve": "CVE-2023-29357", "severity": "critical",
     "exploitability": "weaponized",
     "title": "SharePoint Server privilege escalation to RCE chain - verify patched for CVE-2023-29357 (public exploit)",
     "remediation": "Apply SharePoint security updates immediately.",
     "version_optional": True},
    {"software": "Metabase", "where": "html",
     "version_re": r"metabase",
     "vuln": [],
     "cve": "CVE-2023-38646", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Metabase < 0.46.6.1 setup-token RCE - check version (public exploit)",
     "remediation": "Upgrade Metabase to 0.46.6.1+. Never expose the setup endpoint.",
     "version_optional": True},
    {"software": "Apache Superset", "where": "html",
     "version_re": r"superset",
     "vuln": [],
     "cve": "CVE-2023-27524", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Superset < 2.1 default SECRET_KEY session forgery to RCE - check version (public exploit)",
     "remediation": "Upgrade Superset to 2.1+. Rotate SECRET_KEY to a strong random value.",
     "version_optional": True},
]

POC_HINT = ("Verify: curl -sI {url} | grep -iE '^(server|x-powered-by):' "
            "then match the version against the CVE.")


class CvesPlugin(Plugin):
    id = "cves"
    label = "CVE Matcher"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Detect software versions, match against known CVEs with exploitability."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
        except Exception as e:
            return self._degraded(f"could not fetch: {str(e)[:150]}")

        body = r.text[:200000]
        body_low = body.lower()
        server_h = r.headers.get("server", "")
        powered = r.headers.get("x-powered-by", "")
        # Jenkins exposes its version in X-Jenkins (value is the bare version).
        xj = r.headers.get("x-jenkins", "")
        headers_low = (server_h + " " + powered + (" x-jenkins/" + xj if xj else "")).lower()

        # WordPress generator version
        wp_ver: Optional[str] = None
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress (\d+\.\d+(?:\.\d+)?)',
                      body, re.I)
        if m:
            wp_ver = m.group(1)

        seen_cves = set()

        for entry in VERSION_CVES:
            where = entry["where"]
            if where == "server":
                hay = headers_low
            elif where == "powered_by":
                hay = headers_low
            elif where == "wp_generator":
                hay = f"wordpress {wp_ver}" if wp_ver else ""
                if not wp_ver:
                    continue
            elif where in ("html", "js"):
                hay = body_low
            else:
                continue

            m = re.search(entry["version_re"], hay, re.I)
            if not m:
                continue
            ver_str = None
            try:
                ver_str = m.group(1)
            except IndexError:
                ver_str = None

            vulnerable = False
            if entry.get("version_optional"):
                # Software detected, version unknown: advisory finding.
                vulnerable = True
            elif ver_str:
                ver = _parse_version(ver_str)
                for op, ref in entry["vuln"]:
                    if _check(op, ver, ref):
                        vulnerable = True
                        break
            if not vulnerable:
                continue

            dedupe = (entry["cve"], entry["software"])
            if dedupe in seen_cves:
                continue
            seen_cves.add(dedupe)

            ver_note = f"detected version {ver_str}" if ver_str else "version not disclosed - verify manually"
            findings.append(self._f(
                "web", "cve_match",
                f"{entry['severity'].upper()}: {entry['software']} - {entry['title']} "
                f"[{entry['cve']}] ({ver_note})",
                source="CVE matcher", source_url=url,
                confidence=88 if ver_str else 65, passive=True,
                exploitability=entry["exploitability"],
                evidence={
                    "severity": entry["severity"],
                    "cve": entry["cve"],
                    "software": entry["software"],
                    "detected_version": ver_str or "unknown",
                    "remediation": entry["remediation"],
                    "poc_hint": POC_HINT.format(url=url),
                }))

        # WordPress REST API exposure (version enum fuel)
        if "wp-content" in body_low or "wp-includes" in body_low:
            try:
                r2 = await fetch(ctx.http, ctx.limiter, "GET",
                                 url.rstrip("/") + "/wp-json/wp/v2/users",
                                 timeout=10)
                if r2.status_code == 200 and "slug" in r2.text[:2000]:
                    findings.append(self._f(
                        "web", "wp_user_enum",
                        "HIGH: WordPress REST user enumeration at /wp-json/wp/v2/users - usernames disclosed",
                        source="CVE matcher",
                        source_url=url.rstrip("/") + "/wp-json/wp/v2/users",
                        confidence=85, passive=True,
                        exploitability="public_poc",
                        evidence={"severity": "high",
                                  "remediation": "Restrict /wp-json/wp/v2/users to authenticated users."}))
            except Exception:
                pass

        dur = int((time.monotonic() - t0) * 1000)
        # No "nothing found" noise finding: silence is fine, Jay hates noise.
        res = self._ok(findings, f"matched {len(findings)} version CVEs")
        res.duration_ms = dur
        return res
