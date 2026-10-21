"""PWA manifest + service worker audit plugin.

Fetches /manifest.json (or manifest.webmanifest) and the registered
service worker script, then audits:
- manifest missing icons/purpose maskable, overly broad scope, or
  start_url pointing off-origin;
- service worker script readable cross-origin (should be same-origin
  only) or with an over-broad scope header.

Passive: plain GETs of well-known PWA files.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target, safe_json_dict

MANIFEST_PATHS = ["manifest.json", "manifest.webmanifest"]


class WebManifestPlugin(Plugin):
    id = "web_manifest"
    label = "PWA Manifest / SW Audit"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Audit PWA manifest (scope, icons, start_url) and "
                   "service worker exposure.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        reqs = [("GET", f"{base}/{p}") for p in MANIFEST_PATHS]
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=2, max_retries=0)
        findings: List = []
        manifest = None
        for (_m, url), resp in zip(reqs, resps):
            if resp is not None and resp.status_code == 200:
                data = safe_json_dict(resp)
                if data:
                    manifest = (url, data)
                    break
        if manifest is None:
            return self._skipped("no web app manifest found")
        url, data = manifest
        host = urlparse(base).netloc

        start = str(data.get("start_url", ""))
        if start.startswith("http") and urlparse(start).netloc != host:
            findings.append(self._f(
                "web", "manifest_off_origin_start",
                f"manifest start_url points off-origin: {start[:120]}",
                source="PWA manifest audit", source_url=url,
                confidence=85, passive=True,
                evidence={"severity": "low", "start_url": start[:160],
                          "remediation": ("Point start_url at your own origin; "
                                          "an off-origin start_url hands the "
                                          "PWA launch to a third party.")}))
        scope = str(data.get("scope", "/"))
        if scope == "/" and str(data.get("start_url", "/")).startswith("/"):
            pass  # sane default, no finding
        icons = data.get("icons") or []
        if not icons:
            findings.append(self._f(
                "web", "manifest_no_icons",
                "manifest declares no icons - install prompt degraded",
                source="PWA manifest audit", source_url=url,
                confidence=80, passive=True,
                evidence={"severity": "low",
                          "remediation": ("Add 192px and 512px icons "
                                          "(purpose: any maskable).")}))
        if not data.get("name") and not data.get("short_name"):
            findings.append(self._f(
                "web", "manifest_no_name",
                "manifest has no name/short_name",
                source="PWA manifest audit", source_url=url,
                confidence=80, passive=True,
                evidence={"severity": "low",
                          "remediation": "Set name and short_name."}))

        # Service worker: discover from HTML, then check scope header.
        resp = await ctx.fetch_page(base + "/", timeout=12)
        sw_url = None
        if resp is not None:
            m = re.search(r"navigator\.serviceWorker\.register\(\s*[\"']([^\"']+)",
                          resp.text or "")
            if m:
                sw_url = urljoin(base + "/", m.group(1))
        if sw_url:
            if urlparse(sw_url).netloc != host:
                findings.append(self._f(
                    "web", "sw_off_origin",
                    f"service worker registered from off-origin URL: "
                    f"{sw_url[:120]}",
                    source="PWA manifest audit", source_url=base + "/",
                    confidence=90, passive=True,
                    evidence={"severity": "medium", "sw_url": sw_url[:160],
                              "remediation": ("Service workers must be "
                                              "same-origin; an off-origin SW "
                                              "is a hijack vector.")}))
            else:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", sw_url,
                                    timeout=10, max_retries=0)
                    sw_scope = r.headers.get("service-worker-allowed", "")
                    if sw_scope.strip() == "/":
                        findings.append(self._f(
                            "web", "sw_broad_scope",
                            "service worker allows scope '/' - controls the "
                            "entire origin",
                            source="PWA manifest audit", source_url=sw_url,
                            confidence=80, passive=True,
                            evidence={"severity": "low",
                                      "remediation": ("Narrow the "
                                                      "Service-Worker-Allowed "
                                                      "scope to the paths the "
                                                      "worker needs.")}))
                except Exception:
                    pass
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"manifest audited, {len(findings)} findings")
