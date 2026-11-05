"""Nikto-style web server scanner (Tier-4 Vuln/CVE).

Native re-implementation of the classic Nikto checks, detection only:
  * outdated / end-of-life Server and X-Powered-By banners,
  * dangerous CGI and well-known file paths confirmed by status code
    (existence only - contents are never downloaded or used),
  * missing-security-header COMBO check (a single missing header is
    noise; Nikto-style value is in the aggregate posture),
  * default / leftover files (readme, license, config samples).

Safe GET probes via the shared probe cache. No payloads, no writes.
"""
from __future__ import annotations

import re
import time
from typing import List, Tuple

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (regex on banner, label, severity) - end-of-life / ancient banners.
EOL_BANNERS: List[Tuple[str, str, str]] = [
    (r"apache/1\.", "Apache 1.x (EOL since 2010)", "high"),
    (r"apache/2\.0", "Apache 2.0 (EOL since 2005)", "high"),
    (r"apache/2\.2", "Apache 2.2 (EOL since 2017)", "high"),
    (r"microsoft-iis/[1-6]\.", "IIS 6 or older (EOL, public RCEs)", "high"),
    (r"microsoft-iis/7\.", "IIS 7.x (EOL since 2020)", "medium"),
    (r"nginx/0\.", "nginx 0.x (ancient)", "medium"),
    (r"nginx/1\.[0-9]\.", "nginx 1.0-1.9 (EOL branches)", "medium"),
    (r"php/[1-5]\.", "PHP 5 or older (EOL, many public RCEs)", "high"),
    (r"php/7\.[0-3]", "PHP 7.0-7.3 (EOL)", "medium"),
    (r"openssl/0\.", "OpenSSL 0.x (Heartbleed-era and older)", "high"),
    (r"openssl/1\.0\.1[a-f]?\b", "OpenSSL 1.0.1 (Heartbleed range)", "high"),
]

# path -> (key, label, severity). 200 (or 401 on admin surfaces) fires.
DANGEROUS_PATHS: List[Tuple[str, str, str, str]] = [
    ("/cgi-bin/test-cgi", "nikto_cgi_test", "CGI test-cgi script exposed "
     "(classic info disclosure)", "medium"),
    ("/cgi-bin/printenv", "nikto_cgi_printenv", "CGI printenv script "
     "exposed (environment disclosure)", "medium"),
    ("/cgi-bin/php", "nikto_cgi_php", "PHP-as-CGI binary exposed "
     "(argument injection history)", "high"),
    ("/server-info", "nikto_server_info", "Apache mod_info server-info "
     "page exposed", "medium"),
    ("/server-status", "nikto_server_status", "Apache server-status "
     "page exposed", "medium"),
    ("/icons/README", "nikto_icons_readme", "Apache icons README "
     "present (default install fingerprint)", "low"),
    ("/manual/", "nikto_manual", "Apache manual directory present "
     "(default install fingerprint)", "low"),
    ("/phpmyadmin/", "nikto_phpmyadmin", "phpMyAdmin login surface "
     "exposed", "medium"),
    ("/.htaccess", "nikto_htaccess", ".htaccess file directly "
     "readable", "medium"),
    ("/web.config", "nikto_web_config", "IIS web.config directly "
     "readable", "high"),
    ("/crossdomain.xml", "nikto_crossdomain", "crossdomain.xml "
     "present (check policy scope)", "low"),
    ("/clientaccesspolicy.xml", "nikto_clientaccesspolicy",
     "clientaccesspolicy.xml present", "low"),
]

DEFAULT_FILES: List[Tuple[str, str]] = [
    ("/readme.html", "readme.html (CMS version disclosure)"),
    ("/license.txt", "license.txt (CMS version disclosure)"),
    ("/RELEASE_NOTES.txt", "RELEASE_NOTES.txt leftover"),
    ("/config.sample.php", "config.sample.php leftover sample"),
    ("/php.ini", "php.ini directly readable"),
]

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options",
                    "referrer-policy"]

CANARY = "/rx4-canary-7f3a9-nonexistent"


def _differs(resp, canary) -> bool:
    """True when a 200 response materially differs from the canary
    probe (i.e. it is not the host's catch-all soft-404 page)."""
    try:
        if abs(int(resp.get("length") or 0)
               - int(canary.get("length") or 0)) > 128:
            return True
        rc = (resp.get("headers") or {}).get("content-type", "")
        cc = (canary.get("headers") or {}).get("content-type", "")
        return bool(rc) and rc != cc
    except Exception:
        return False


def check_banners(server: str, powered_by: str) -> List[Tuple[str, str, str]]:
    out = []
    for banner in (server or "", powered_by or ""):
        for rx, label, sev in EOL_BANNERS:
            if re.search(rx, banner, re.I):
                out.append((banner, label, sev))
    return out


class NiktoScanPlugin(Plugin):
    id = "nikto_scan"
    label = "Nikto Web Server Scan"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Nikto-style web server checks: EOL banners, "
                   "dangerous CGI/file paths by status, missing "
                   "security-header combos, default files. GET only.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        page = await ctx.fetch_page(base + "/", timeout=12)
        if page is None:
            return self._degraded("homepage unreachable")
        headers = {str(k).lower(): str(v)
                   for k, v in dict(page.get("headers") or {}).items()}
        findings: List[Finding] = []

        for banner, label, sev in check_banners(headers.get("server", ""),
                                                headers.get(
                                                    "x-powered-by", "")):
            findings.append(self._f(
                "web", "nikto_outdated_banner",
                f"Outdated server banner {banner!r}: {label}",
                source="nikto banner check", source_url=base + "/",
                confidence=85, passive=False,
                evidence={"severity": sev, "banner": banner,
                          "remediation": (
                              "Upgrade the server/runtime to a supported "
                              "release and suppress version banners.")}))
        if headers.get("x-powered-by"):
            findings.append(self._f(
                "web", "nikto_powered_by_disclosure",
                f"X-Powered-By discloses stack: "
                f"{headers['x-powered-by'][:80]}",
                source="nikto header check", source_url=base + "/",
                confidence=90, passive=True,
                evidence={"severity": "low",
                          "remediation": "Remove the X-Powered-By header "
                                         "(expose_php=Off / header unset)."}))

        missing = [h for h in SECURITY_HEADERS if h not in headers]
        if len(missing) >= 3:
            findings.append(self._f(
                "web", "nikto_missing_security_headers",
                f"{len(missing)}/5 security headers missing: "
                + ", ".join(missing),
                source="nikto header combo", source_url=base + "/",
                confidence=90, passive=True,
                evidence={"severity": "medium", "missing": missing,
                          "remediation": (
                              "Add the missing security headers at the "
                              "edge/server layer and re-scan.")}))

        canary = await ctx.probe(base + CANARY, timeout=8)
        catchall = int(canary.get("status") or 0) == 200
        suppressed = 0
        for path, key, label, sev in DANGEROUS_PATHS:
            r = await ctx.probe(base + path, timeout=8)
            if (catchall and r.get("status") == 200
                    and not _differs(r, canary)):
                suppressed += 1
                continue
            if r.get("status") in (200, 401):
                findings.append(self._f(
                    "web", key, f"{label} [{path} -> HTTP "
                    f"{r.get('status')}]",
                    source="nikto path probe", source_url=base + path,
                    confidence=85 if r.get("status") == 200 else 65,
                    passive=False,
                    evidence={"severity": sev, "path": path,
                              "status": r.get("status"),
                              "remediation": (
                                  "Remove or access-restrict this path; "
                                  "it is a default/dangerous surface.")}))
        for path, label in DEFAULT_FILES:
            r = await ctx.probe(base + path, timeout=8)
            if (catchall and r.get("status") == 200
                    and not _differs(r, canary)):
                suppressed += 1
                continue
            if r.get("status") == 200:
                findings.append(self._f(
                    "web", "nikto_default_file",
                    f"Default/leftover file present: {label} [{path}]",
                    source="nikto path probe", source_url=base + path,
                    confidence=80, passive=False,
                    evidence={"severity": "low", "path": path,
                              "remediation": "Delete leftover default "
                                             "files from the web root."}))
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"nikto checks done: {len(findings)} findings"
                   + (f"; catch-all host: {suppressed} soft-404 "
                      "path hits suppressed" if catchall else ""))
