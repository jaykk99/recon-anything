"""Third-party tracker inventory plugin.

Parses the homepage for known tracker/adtech script hosts (Google
Analytics/Tag Manager, Meta Pixel, TikTok, Hotjar, Segment, ad
networks) and reports the inventory with a privacy note. Not a
vulnerability - but Jay asked for full asset visibility, and an
unknown third party with script access is a supply-chain fact worth
knowing.

Passive: parses the already-fetched homepage HTML. No extra requests.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

# host fragment -> friendly name
TRACKERS = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "connect.facebook.net": "Meta Pixel",
    "facebook.com/tr": "Meta Pixel",
    "analytics.tiktok.com": "TikTok Pixel",
    "hotjar.com": "Hotjar",
    "cdn.segment.com": "Segment",
    "fullstory.com": "FullStory",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "doubleclick.net": "Google DoubleClick",
    "googlesyndication.com": "Google AdSense",
    "adsystem.com": "Amazon Ads",
    "criteo.com": "Criteo",
    "outbrain.com": "Outbrain",
    "taboola.com": "Taboola",
    "clarity.ms": "Microsoft Clarity",
    "matomo": "Matomo",
    "plausible.io": "Plausible",
    "cdn.jsdelivr.net/npm/@fingerprintjs": "FingerprintJS",
    "stripe.com/v3": "Stripe.js",
    "paypal.com/sdk": "PayPal SDK",
    "challenges.cloudflare.com": "Cloudflare Turnstile",
    "recaptcha": "reCAPTCHA",
}

SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)


class TrackersPlugin(Plugin):
    id = "trackers"
    label = "Third-Party Trackers"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Inventory third-party trackers/adtech with script "
                   "access on the page.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable")
        html = (resp.text or "")[:300000]

        found = {}
        for m in SRC_RE.finditer(html):
            src = m.group(1).lower()
            for frag, name in TRACKERS.items():
                if frag in src and name not in found:
                    found[name] = src[:160]
        findings: List = []
        if found:
            findings.append(self._f(
                "web", "third_party_trackers",
                f"{len(found)} third-party trackers with script access: "
                + ", ".join(sorted(found)),
                source="tracker inventory", source_url=base + "/",
                confidence=90, passive=True,
                evidence={"severity": "low", "trackers": sorted(found),
                          "remediation": (
                              "Informational: each tracker is a supply-chain "
                              "dependency with script access. Keep the list "
                              "minimal and pin versions where possible.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            elapsed_s=round(time.monotonic() - t0, 2),
            reason=f"inventoried {len(found)} third-party trackers")
