"""Droopescan-style CMS fingerprinting (Tier-4 Vuln/CVE).

Droope's model: identify WHICH CMS a site runs and hint its version,
across many CMSes, from cheap fingerprints - generator meta tags,
X-Generator headers, CMS-specific readme / changelog / manifest
paths whose bodies carry version strings. Covers WordPress, Joomla,
Drupal, SilverStripe and Moodle. Detection only, GET only.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
    re.I)

# cms -> (path, version regex or None)
VERSION_PATHS: Dict[str, List[Tuple[str, Optional[str]]]] = {
    "wordpress": [("/readme.html", r"Version\s+(\d+\.\d+(?:\.\d+)?)")],
    "joomla": [("/language/en-GB/en-GB.xml",
                r"<version>(\d+\.\d+(?:\.\d+)?)</version>"),
               ("/administrator/manifests/files/joomla.xml",
                r"<version>(\d+\.\d+(?:\.\d+)?)</version>")],
    "drupal": [("/CHANGELOG.txt", r"Drupal\s+(\d+\.\d+(?:\.\d+)?)"),
               ("/core/CHANGELOG.txt", r"Drupal\s+(\d+\.\d+(?:\.\d+)?)")],
    "silverstripe": [("/framework/silverstripe_version",
                      r"(\d+\.\d+(?:\.\d+)?)"),
                     ("/silverstripe-cache/silverstripe_version",
                      r"(\d+\.\d+(?:\.\d+)?)")],
    "moodle": [("/lib/upgrade.txt", r"(\d+\.\d+(?:\.\d+)?)")],
}

# cms -> body markers (lowercase substrings)
BODY_MARKERS: Dict[str, List[str]] = {
    "wordpress": ["wp-content/", "wp-includes/"],
    "joomla": ["/media/jui/", "joomla! - open source content management"],
    "drupal": ["drupal-settings-json", "/sites/default/files",
               "drupal.org"],
    "silverstripe": ["silverstripe", "/framework/thirdparty"],
    "moodle": ["moodle", "theme/boost", "/lib/javascript.php"],
}


def fingerprint(html: str, headers: Dict[str, str]) -> Dict[str, str]:
    """cms -> version-or-empty from generator tag / headers / body."""
    out: Dict[str, str] = {}
    low = (html or "").lower()
    gen = ""
    m = GEN_RE.search(html or "")
    if m:
        gen = m.group(1)
    gen_low = gen.lower()
    xgen = (headers.get("x-generator") or "").lower()
    for cms in BODY_MARKERS:
        if cms in gen_low or cms in xgen:
            vm = re.search(r"(\d+\.\d+(?:\.\d+)?)", gen or
                           headers.get("x-generator", ""))
            out[cms] = vm.group(1) if vm else ""
        elif any(marker in low for marker in BODY_MARKERS[cms]):
            out.setdefault(cms, "")
    if "wordpress" in out and not out["wordpress"]:
        vm = re.search(r"wordpress\s+(\d+\.\d+(?:\.\d+)?)", gen_low)
        if vm:
            out["wordpress"] = vm.group(1)
    if "drupal" in out and not out["drupal"]:
        vm = re.search(r"drupal\s+(\d+)", gen_low)
        if vm:
            out["drupal"] = vm.group(1)
    return out


class DroopescanScanPlugin(Plugin):
    id = "droopescan_scan"
    label = "Droopescan CMS Fingerprint"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Droopescan-style CMS fingerprinting: WordPress / "
                   "Joomla / Drupal / SilverStripe / Moodle detection "
                   "+ version hints from generator tags and readme / "
                   "changelog / manifest paths.")
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
        html = (page.get("text") or "")[:300000]
        headers = {str(k).lower(): str(v)
                   for k, v in dict(page.get("headers") or {}).items()}
        hits = fingerprint(html, headers)
        findings: List[Finding] = []
        for cms, version in sorted(hits.items()):
            if not version:
                for path, rx in VERSION_PATHS.get(cms, []):
                    r = await ctx.probe(base + path, timeout=8)
                    if r.get("status") == 200 and rx:
                        vm = re.search(rx, r.get("text") or "", re.I)
                        if vm:
                            version = vm.group(1)
                            break
            findings.append(self._f(
                "web", "cms_fingerprint",
                f"CMS fingerprinted: {cms}"
                + (f" {version}" if version else " (version not "
                                                  "exposed)"),
                source="droopescan fingerprint", source_url=base + "/",
                confidence=90 if version else 80, passive=True,
                evidence={"severity": "low", "cms": cms,
                          "version": version or None,
                          "remediation": (
                              f"Keep {cms} and its extensions patched; "
                              "hide generator/version disclosures so "
                              "the exact version is not public.")}))
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"droopescan: {len(hits)} CMS fingerprinted "
                   f"({', '.join(sorted(hits)) or 'none'})")
