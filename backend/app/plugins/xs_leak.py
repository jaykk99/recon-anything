"""Cross-site leak (XS-Leak) detection plugin.

Checks the building blocks attackers use for cross-site leaks:
- Missing COOP / COEP / CORP / Cross-Origin-Opener-Policy headers and the
  Fetch-Metadata resource isolation headers.
- Framing protections (X-Frame-Options / frame-ancestors) on the homepage
  and on likely-sensitive paths - a frameable sensitive page is the
  classic XS-Leak oracle.
- Status-code oracle candidates: same endpoint behaving differently for
  two safe, unauthenticated requests (detection only, no login bypass).
Detection only - no cross-origin attacks are performed.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

ISOLATION_HEADERS = {
    "cross-origin-embedder-policy": "COEP",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
}

SENSITIVE_PATHS = ["/", "/account", "/profile", "/settings", "/admin",
                   "/dashboard", "/login", "/api/me", "/api/user"]


class XsLeakPlugin(Plugin):
    id = "xs_leak"
    label = "Cross-Site Leak Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Checks COOP/COEP/CORP isolation headers, framing "
                   "protections, and status-code oracle candidates.")
    phase = 1

    async def _get(self, ctx: Ctx, url: str) -> Optional[Dict]:
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                            max_retries=1, follow_redirects=True)
            try:
                txt = r.text[:8000]
            except Exception:
                txt = ""
            return {"status": r.status_code,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "text": txt, "url": str(r.url)}
        except Exception:
            return None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

        findings: List[Finding] = []

        home = await self._get(ctx, base + "/")
        if home is None:
            return self._degraded("homepage unreachable")

        h = home["headers"]

        # --- 1. Cross-origin isolation headers --------------------------------
        missing = [label for hdr, label in ISOLATION_HEADERS.items() if hdr not in h]
        if missing:
            findings.append(self._f(
                "web", "xsleak_no_isolation",
                f"Missing cross-origin isolation headers on homepage: "
                f"{', '.join(missing)} - the site is exposed to XS-Leak "
                "side-channel attacks (Spectre-class data theft via "
                "cross-origin reads)",
                source="Cross-site leak detector", source_url=base + "/",
                confidence=80, passive=True,
                evidence={"severity": "medium", "exploitability": "theoretical",
                          "remediation": "Send Cross-Origin-Opener-Policy: "
                          "same-origin, Cross-Origin-Embedder-Policy: "
                          "require-corp and Cross-Origin-Resource-Policy: "
                          "same-origin on sensitive responses."}))
        # Fetch-Metadata: sites that vary on Sec-Fetch-* break naive oracles.
        if "vary" not in h or "sec-fetch" not in h.get("vary", "").lower():
            findings.append(self._f(
                "web", "xsleak_no_fetch_metadata",
                "Homepage does not Vary on Sec-Fetch-* request metadata - "
                "the app is not using Fetch Metadata to block cross-site "
                "inclusion attacks",
                source="Cross-site leak detector", source_url=base + "/",
                confidence=65, passive=True,
                evidence={"severity": "low", "exploitability": "theoretical",
                          "remediation": "Adopt Fetch Metadata (Sec-Fetch-Site "
                          "/ Sec-Fetch-Mode) checks server-side and add "
                          "Vary: Sec-Fetch-Site where responses differ."}))

        # --- 2. Framing protections on homepage + sensitive paths -------------
        def framing_status(headers: Dict[str, str]) -> str:
            xfo = headers.get("x-frame-options", "").upper()
            csp = headers.get("content-security-policy", "").lower()
            if "frame-ancestors" in csp:
                return "csp-frame-ancestors"
            if xfo in ("DENY", "SAMEORIGIN"):
                return f"xfo-{xfo}"
            return "none"

        home_frame = framing_status(h)
        if home_frame == "none":
            findings.append(self._f(
                "web", "xsleak_frameable_home",
                "Homepage is frameable (no X-Frame-Options / frame-ancestors) "
                "- enables clickjacking and frame-based XS-Leak oracles",
                source="Cross-site leak detector", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": "medium", "exploitability": "public_poc",
                          "remediation": "Send X-Frame-Options: DENY (or "
                          "SAMEORIGIN) and a CSP frame-ancestors directive "
                          "on every page."}))

        for path in SENSITIVE_PATHS[1:]:
            page = await self._get(ctx, base + path)
            if page is None or page["status"] in (0, 404, 410):
                continue
            if framing_status(page["headers"]) == "none" and page["status"] == 200:
                findings.append(self._f(
                    "web", "xsleak_frameable_sensitive",
                    f"Sensitive path {path} is frameable (HTTP "
                    f"{page['status']}, no X-Frame-Options / frame-ancestors) "
                    "- a prime XS-Leak / clickjacking oracle target",
                    source="Cross-site leak detector",
                    source_url=page["url"],
                    confidence=80, passive=True,
                    evidence={"severity": "medium",
                              "exploitability": "public_poc",
                              "remediation": f"Add X-Frame-Options: DENY and "
                              f"CSP frame-ancestors to {path}; require auth "
                              "and anti-CSRF on state-changing actions."}))

        # --- 3. Status-code oracle candidates -----------------------------------
        # Same resource, two safe unauthenticated requests with a trivial
        # parameter difference. Different status/body length = the endpoint
        # leaks state to cross-site status-code oracles.
        oracle = await self._get(ctx, base + "/?xsleak_a=1")
        oracle2 = await self._get(ctx, base + "/?xsleak_b=2")
        if oracle and oracle2 and oracle["status"] and oracle2["status"]:
            if (oracle["status"] != oracle2["status"]
                    or abs(len(oracle["text"]) - len(oracle2["text"])) > 500):
                findings.append(self._f(
                    "web", "xsleak_status_oracle",
                    f"Homepage responds differently to trivial query changes "
                    f"({oracle['status']}/{len(oracle['text'])}b vs "
                    f"{oracle2['status']}/{len(oracle2['text'])}b) - response "
                    "varies on attacker-influenced input, usable as an "
                    "XS-Leak status oracle",
                    source="Cross-site leak detector", source_url=base + "/",
                    confidence=60, passive=False,
                    evidence={"severity": "low", "exploitability": "theoretical",
                              "remediation": "Make responses uniform for "
                              "unauthenticated visitors where possible, and "
                              "ship COOP/COEP so cross-site reads are "
                              "blocked regardless."}))

        # --- 4. CORP on subresource-ish probe -------------------------------------
        # A JSON-ish API path without CORP can be probed cross-origin.
        api = await self._get(ctx, base + "/api/")
        if api and api["status"] == 200 and "cross-origin-resource-policy" not in api["headers"]:
            findings.append(self._f(
                "web", "xsleak_api_no_corp",
                "/api/ responds 200 without Cross-Origin-Resource-Policy - "
                "API responses may be readable cross-origin where the "
                "browser allows it",
                source="Cross-site leak detector", source_url=base + "/api/",
                confidence=60, passive=True,
                evidence={"severity": "low", "exploitability": "theoretical",
                          "remediation": "Send Cross-Origin-Resource-Policy: "
                          "same-origin on API responses and require auth "
                          "tokens that browsers do not attach cross-site."}))

        if not findings:
            findings.append(self._f(
                "web", "xsleak_clean",
                "Cross-origin isolation headers present, framing protected, "
                "no status-oracle differences detected",
                source="Cross-site leak detector", source_url=base + "/",
                confidence=70, passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, "checked isolation headers, framing, oracles")
        res.duration_ms = dur
        return res
