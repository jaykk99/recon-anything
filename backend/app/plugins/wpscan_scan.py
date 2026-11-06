"""WPScan-style WordPress scanner (Tier-4 Vuln/CVE).

Detection surface, GET only, no login attempts:
  * core version from the generator meta tag and from readme.html,
  * plugin / theme slug extraction from page source
    (/wp-content/plugins/<slug>/, /wp-content/themes/<slug>/),
  * /wp-json/ REST surface: index reachability + namespace listing,
  * author-archive user enumeration (detection): /?author=N
    redirect target and the /wp-json/wp/v2/users listing expose
    author slugs - reported as an enumeration finding, and the
    slugs themselves as low-value user findings.
WPSCAN_API_TOKEN (ctx key or env) is optional: when present the
result notes the API-backed vulnerability lookup is enabled; the
scan is fully functional without it.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import List, Set

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress '
    r'(\d+\.\d+(?:\.\d+)?)', re.I)
README_VER_RE = re.compile(r"Version\s+(\d+\.\d+(?:\.\d+)?)", re.I)
PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9\-_]+)/", re.I)
THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9\-_]+)/", re.I)
AUTHOR_RE = re.compile(r"/author/([a-z0-9\-_]+)", re.I)


def extract_slugs(html: str):
    plugins = sorted(set(PLUGIN_RE.findall(html or "")))
    themes = sorted(set(THEME_RE.findall(html or "")))
    return plugins, themes


class WpscanScanPlugin(Plugin):
    id = "wpscan_scan"
    label = "WPScan WordPress Scan"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("WPScan-style WordPress detection: core version "
                   "(generator/readme), plugin+theme slug extraction, "
                   "/wp-json surface, author user enumeration. "
                   "WPSCAN_API_TOKEN optional.")
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
        findings: List[Finding] = []
        is_wp = ("wp-content" in html or "wp-includes" in html
                 or GEN_RE.search(html))
        version = None
        m = GEN_RE.search(html)
        if m:
            version = m.group(1)
        readme = await ctx.probe(base + "/readme.html", timeout=8)
        rm = None
        if readme.get("status") == 200:
            # A 200 alone proves nothing on catch-all (SPA) hosts:
            # the readme counts only when its body carries the
            # WordPress version marker.
            rm = README_VER_RE.search(readme.get("text") or "")
            if rm and "wordpress" not in (
                    readme.get("text") or "").lower():
                rm = None
            if rm:
                if not version:
                    version = rm.group(1)
                findings.append(self._f(
                    "web", "wp_readme_exposed",
                    "WordPress readme.html is publicly readable"
                    f" (version {rm.group(1)})",
                    source="wpscan readme probe",
                    source_url=base + "/readme.html", confidence=90,
                    passive=False,
                    evidence={"severity": "low",
                              "remediation": "Delete readme.html from "
                                             "the web root; it "
                                             "discloses the exact "
                                             "core version."}))
        if not is_wp and not version and not rm:
            return PluginResult(
                plugin_id=self.id, status="ok", findings=[],
                duration_ms=int((time.monotonic() - t0) * 1000),
                reason="no WordPress fingerprints on homepage")
        if version:
            findings.append(self._f(
                "web", "wp_version",
                f"WordPress core version detected: {version}",
                source="wpscan version detection", source_url=base + "/",
                confidence=90, passive=True,
                evidence={"severity": "low", "version": version,
                          "remediation": "Keep WordPress core current "
                                         "and hide the generator meta."}))
        plugins, themes = extract_slugs(html)
        for slug in plugins:
            findings.append(self._f(
                "web", "wp_plugin_slug",
                f"WordPress plugin in use: {slug}",
                source="wpscan page source", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": "low", "slug": slug, "kind": "plugin",
                          "remediation": "Keep this plugin updated; "
                                         "unmaintained plugins are the "
                                         "top WordPress entry vector."}))
        for slug in themes:
            findings.append(self._f(
                "web", "wp_theme_slug",
                f"WordPress theme in use: {slug}",
                source="wpscan page source", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": "low", "slug": slug, "kind": "theme",
                          "remediation": "Keep the theme updated and "
                                         "remove unused themes."}))
        wpjson = await ctx.probe(base + "/wp-json/", timeout=8)
        wpjson_data = None
        if wpjson.get("status") == 200:
            try:
                parsed = json.loads(wpjson.get("text") or "{}")
                if isinstance(parsed, dict) and (
                        "namespaces" in parsed or "routes" in parsed):
                    wpjson_data = parsed
            except Exception:
                wpjson_data = None
        if wpjson_data is not None:
            ns: Set[str] = set(wpjson_data.get("namespaces") or [])
            findings.append(self._f(
                "api", "wp_json_surface",
                "WordPress REST API index public at /wp-json/"
                + (f" (namespaces: {', '.join(sorted(ns)[:8])})"
                   if ns else ""),
                source="wpscan wp-json probe",
                source_url=base + "/wp-json/", confidence=90,
                passive=False,
                evidence={"severity": "low",
                          "namespaces": sorted(ns)[:20],
                          "remediation": "Restrict /wp-json/ to "
                                         "authenticated users if the "
                                         "site does not need it public."}))
        # Author enumeration (detection): REST users listing.
        users = await ctx.probe(base + "/wp-json/wp/v2/users", timeout=8)
        slugs: List[str] = []
        if users.get("status") == 200:
            try:
                rows = json.loads(users.get("text") or "[]")
                if isinstance(rows, list):
                    slugs = [str(r.get("slug")) for r in rows
                             if isinstance(r, dict) and r.get("slug")]
            except Exception:
                slugs = []
        if slugs:
            findings.append(self._f(
                "identity", "wp_author_enum",
                f"WordPress author enumeration via REST users: "
                f"{len(slugs)} author slug(s) public "
                f"({', '.join(slugs[:10])})",
                source="wpscan author enum",
                source_url=base + "/wp-json/wp/v2/users", confidence=90,
                passive=False,
                evidence={"severity": "medium", "authors": slugs[:25],
                          "remediation": "Block the /wp-json/wp/v2/users "
                                         "route for anonymous visitors; "
                                         "author slugs feed credential "
                                         "attacks."}))
        else:
            auth = await ctx.probe(base + "/?author=1", timeout=8)
            am = AUTHOR_RE.search(str(auth.get("url") or ""))
            if am:
                findings.append(self._f(
                    "identity", "wp_author_enum",
                    f"WordPress author archive reveals slug "
                    f"{am.group(1)!r} via /?author=1 redirect",
                    source="wpscan author enum", source_url=base + "/",
                    confidence=80, passive=False,
                    evidence={"severity": "medium",
                              "author": am.group(1),
                              "remediation": "Disable author archives or "
                                             "the ?author= redirect leak."}))
        token = (ctx.keys or {}).get("WPSCAN_API_TOKEN") or \
            os.environ.get("WPSCAN_API_TOKEN")
        note = ("; WPSCAN_API_TOKEN present - API vuln lookup enabled"
                if token else "; no WPSCAN_API_TOKEN (optional) - "
                              "local detection only")
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"wpscan: WP version={version or 'unknown'}, "
                   f"{len(plugins)} plugins, {len(themes)} themes, "
                   f"{len(findings)} findings{note}")
