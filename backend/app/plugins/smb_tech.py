"""Small-business tech stack detector.

Fingerprints SMB website platforms (WordPress, Shopify, Squarespace,
Wix, Weebly, GoDaddy builder, Webflow, Duda) via generator meta tags,
script URLs, DNS/hosting markers, and response headers. For each
detected platform it runs 3-5 quick misconfiguration checks:
  - debug/verbose error markers on the homepage
  - directory listing on the platform's uploads path
  - exposed backup/config files (platform-specific)
  - missing security headers (X-Frame-Options, CSP,
    X-Content-Type-Options)

All GET-only, read-only. Findings: tech detected (low) plus each
misconfig (low/medium) with remediation.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# platform -> detection regexes (homepage html + response headers)
SMB_SIGS: Dict[str, List[str]] = {
    "wordpress": [r"wp-content", r"wp-includes",
                  r'name="generator"[^>]*wordpress'],
    "shopify": [r"cdn\.shopify\.com", r"myshopify\.com",
                r"x-shopify", r"x-shopid"],
    "squarespace": [r"squarespace\.com", r"static1\.squarespace\.com",
                    r"SQUARESPACE_CONTEXT"],
    "wix": [r"wixstatic\.com", r"parastorage\.com", r"wix\.com"],
    "weebly": [r"weebly\.com", r"weeblycloud\.com",
               r"cdn2\.editmysite\.com"],
    "godaddy": [r"wsimg\.com", r"godaddy.*website builder",
                r"website builder.*godaddy", r"secureserver\.net"],
    "webflow": [r"webflow\.com", r'data-wf-|name="generator"[^>]*webflow'],
    "duda": [r"dudamobile\.com", r"dudaone\.com",
             r"static\.dudamobile\.com"],
}

# platform -> uploads dir to probe for directory listing
UPLOAD_PATHS = {
    "wordpress": "/wp-content/uploads/",
    "weebly": "/uploads/",
    "godaddy": "/uploads/",
    "duda": "/uploads/",
}

# platform -> backup/config files that must not be web-reachable
BACKUP_FILES = {
    "wordpress": ["/wp-config.php.bak", "/wp-config.php.old",
                  "/wp-config.php.save"],
    "webflow": [],
    "shopify": [],
    "squarespace": [],
    "wix": [],
    "weebly": ["/index.php.bak", "/index.html.bak"],
    "godaddy": ["/index.html.bak", "/config.php.bak"],
    "duda": ["/index.php.bak"],
}

DEBUG_MARKERS = re.compile(
    r"WP_DEBUG|Fatal error:|Call to undefined function|"
    r"Notice:\s+Undefined|Warning:\s+(require|include)|"
    r"Stack trace:|debug=true|<!--\s*DEBUG", re.I)

DIRLIST_MARKERS = re.compile(
    r"Index of /|<title>Directory listing|<h1>Index of", re.I)

HEADER_CHECKS = {
    "x-frame-options": ("missing clickjacking protection (X-Frame-Options)",
                        "Add X-Frame-Options: DENY or SAMEORIGIN."),
    "content-security-policy": ("missing Content-Security-Policy header",
                                "Deploy a Content-Security-Policy; start in "
                                "report-only mode, then enforce."),
    "x-content-type-options": ("missing X-Content-Type-Options: nosniff",
                               "Add X-Content-Type-Options: nosniff to stop "
                               "MIME sniffing."),
}


class SmbTechPlugin(Plugin):
    id = "smb_tech"
    label = "SMB Tech Stack"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Detect small-business website platforms (Shopify, "
                   "Squarespace, Wix, Weebly, GoDaddy, Webflow, Duda) "
                   "and flag quick misconfigs. GET only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        async def get(path: str, timeout: int = 10):
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base + path,
                                timeout=timeout, max_retries=1,
                                follow_redirects=True)
                return r.status_code, r.text[:200000], dict(r.headers)
            except Exception:
                return 0, "", {}

        def add(key, value, conf, sev, remediation, url=None):
            findings.append(self._f(
                "web", key, value, source="SMB tech stack",
                source_url=url or base, confidence=conf, passive=passive,
                evidence={"severity": sev, "remediation": remediation}))

        status, html, hdrs = await get("/", timeout=20)
        if status == 0:
            res = self._degraded("could not fetch homepage")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        text = html + " " + " ".join(f"{k}: {v}" for k, v in hdrs.items())
        hdrs_l = {k.lower(): v for k, v in hdrs.items()}

        detected: List[str] = []
        for platform, pats in SMB_SIGS.items():
            if any(re.search(p, text, re.I) for p in pats):
                detected.append(platform)

        if not detected:
            res = self._ok([], "no SMB platform fingerprinted")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        for platform in detected:
            add("smb_tech_detected",
                f"SMB tech detected: {platform.title()}",
                80, "low",
                "Inventory this platform; confirm it is patched and "
                "misconfigs below are fixed.",
                base)

        # ---- shared checks across detected platforms ----
        # 1) debug / verbose error markers
        if DEBUG_MARKERS.search(html):
            add("smb_debug_output",
                "MEDIUM: debug or PHP error output visible on the homepage "
                "- verbose errors aid attackers",
                70, "medium",
                "Disable debug output and display_errors in production.",
                base)

        # 2) missing security headers (platform-specific severity note)
        missing = [h for h in HEADER_CHECKS if h not in hdrs_l]
        if missing:
            details = "; ".join(HEADER_CHECKS[h][0] for h in missing)
            add("smb_missing_headers",
                f"LOW: missing security headers: {details}",
                75, "low",
                " ".join(HEADER_CHECKS[h][1] for h in missing),
                base)

        # 3) uploads directory listing (platform uploads path)
        for platform in detected:
            upath = UPLOAD_PATHS.get(platform)
            if not upath:
                continue
            st, body, _ = await get(upath, timeout=8)
            if st == 200 and DIRLIST_MARKERS.search(body):
                add("smb_dir_listing",
                    f"MEDIUM: directory listing enabled on {upath} - "
                    f"file inventory exposed",
                    85, "medium",
                    f"Disable directory listing for {upath} "
                    f"(Options -Indexes or equivalent).",
                    base + upath)

        # 4) exposed backup/config files (platform-specific)
        for platform in detected:
            for p in BACKUP_FILES.get(platform, []):
                st, body, _ = await get(p, timeout=8)
                if st == 200 and len(body.strip()) > 20:
                    add("smb_backup_exposed",
                        f"HIGH: backup/config file {p} is web-reachable "
                        f"({len(body)} bytes)",
                        90, "high",
                        f"Remove {p} from the web root and rotate any "
                        f"credentials it contained.",
                        base + p)

        # 5) generator/version meta disclosure per platform
        m = re.search(r'<meta[^>]+name="generator"[^>]+content="([^"]+)"',
                      html, re.I)
        if m:
            gen = m.group(1)[:120]
            if re.search(r"[\d.]{3,}", gen):
                add("smb_version_disclosure",
                    f"LOW: generator meta discloses stack version: {gen}",
                    70, "low",
                    "Remove or genericize the generator meta tag; version "
                    "details aid targeting.",
                    base)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{len(detected)} platform(s) detected, "
                       f"{len(findings)} findings")
        res.duration_ms = dur
        return res
