"""Gift card infrastructure mapper.

Jay's order: scan a site like apple.com, go to gift card findings, and see
the gift card INFRASTRUCTURE - the backend system, API endpoints, which
provider they use, how purchase/redeem/balance-check flows work.

This is recon on exposed infrastructure only: we map endpoints, providers,
and flows visible in HTML/JS. No unauthorized access, no redemption
attempts, no balance checks against real accounts.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Gift card platform providers (third-party systems companies use)
PROVIDERS = [
    ("InComm", r"incomm|incomm\.com", 85),
    ("Blackhawk Network", r"blackhawk|bhnetwork|hawk\s?incentives", 85),
    ("Givex", r"givex", 85),
    ("Paytronix", r"paytronix", 85),
    ("Buyatab", r"buyatab", 85),
    ("Yiftee", r"yiftee", 85),
    ("National Gift Card", r"nationalgiftcard|ngc\s", 80),
    ("CashStar", r"cashstar", 85),
    ("GiveSmart", r"givesmart", 80),
    ("Tango Card", r"tangocard|runa\.io", 85),
    ("Stripe Issuing", r"stripe.*issuing|issuing\.card", 80),
    ("Marqeta", r"marqeta", 80),
    ("Apple Gift Card", r"apple.*gift\s?card|giftcard\.apple", 90),
]

# Gift card API endpoint patterns (what the backend exposes)
ENDPOINT_PATTERNS = [
    (r'["\'](/[a-zA-Z0-9_\-./]*gift[-_]?cards?[a-zA-Z0-9_\-./?]*)["\']', "giftcard_api"),
    (r'["\'](/[a-zA-Z0-9_\-./]*gift[-_]?certificates?[a-zA-Z0-9_\-./?]*)["\']', "giftcert_api"),
    (r'["\'](/[a-zA-Z0-9_\-./]*redeem[a-zA-Z0-9_\-./?]*)["\']', "redeem_endpoint"),
    (r'["\'](/[a-zA-Z0-9_\-./]*balance[a-zA-Z0-9_\-./?]*)["\']', "balance_endpoint"),
    (r'["\'](/[a-zA-Z0-9_\-./]*activate[a-zA-Z0-9_\-./?]*)["\']', "activate_endpoint"),
]

# Flow keywords: purchase / redeem / balance-check / reload
FLOW_PATTERNS = [
    ("purchase", r"buy[-\s]?a[-\s]?gift[-\s]?card|purchase[-\s]?gift[-\s]?card|gift[-\s]?card[-\s]?checkout", 75),
    ("redeem", r"redeem[-\s]?(a[-\s]?)?gift[-\s]?card|apply[-\s]?gift[-\s]?card", 75),
    ("balance_check", r"(check|verify)[-\s]?(your[-\s]?)?gift[-\s]?card[-\s]?balance|gift[-\s]?card[-\s]?balance", 75),
    ("reload", r"reload[-\s]?(a[-\s]?)?gift[-\s]?card|add[-\s]?funds", 70),
    ("egift_delivery", r"e[-\s]?gift[-\s]?card[-\s]?delivery|send[-\s]?(a[-\s]?)?gift[-\s]?card", 70),
]

# Gift card number/code formats that might be exposed (detection only)
CODE_PATTERNS = [
    ("giftcard_code", r"\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b", 70),
    ("giftcard_pin", r"gift[-\s]?card[-\s]?(pin|code|number)[\"']?\s*[:=]\s*[\"']?[A-Z0-9]{6,20}", 80),
]


class GiftCardsPlugin(Plugin):
    id = "giftcards"
    label = "Gift Card Infrastructure"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Map gift card systems: providers, API endpoints, purchase/redeem/balance flows."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []

        # Fetch homepage + likely gift card pages
        pages = [base + "/"]
        for path in ["/gift-cards", "/giftcards", "/gift-card", "/giftcard",
                     "/gifts", "/egift", "/e-gift-cards"]:
            pages.append(base + path)

        all_text = ""
        js_urls = []
        for url in pages[:4]:
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                                   timeout=12, max_retries=1)
                if resp and resp.status_code == 200:
                    all_text += resp.text[:200000] + "\n"
                    for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text):
                        js_urls.append(urljoin(url, m.group(1)))
            except Exception:
                continue
            if len(all_text) > 400000:
                break

        # Fetch a few JS bundles for provider/endpoint references
        for js_url in js_urls[:5]:
            try:
                jr = await fetch(ctx.http, ctx.limiter, "GET", js_url,
                                 timeout=10, max_retries=1)
                if jr and jr.status_code == 200:
                    all_text += jr.text[:150000] + "\n"
            except Exception:
                continue
            if len(all_text) > 800000:
                break

        if not all_text:
            return self._skipped("could not fetch pages")

        # 1. Providers: which gift card platform do they use?
        seen_providers = set()
        for name, pattern, conf in PROVIDERS:
            if name in seen_providers:
                continue
            m = re.search(pattern, all_text, re.I)
            if m:
                seen_providers.add(name)
                ctx_text = all_text[max(0, m.start() - 80):m.end() + 80]
                findings.append(self._f(
                    "web", "giftcard_provider",
                    f"Gift card provider: {name}",
                    "gift card infrastructure recon",
                    confidence=conf,
                    evidence={"severity": "low",
                              "provider": name,
                              "context": ctx_text[:200].strip(),
                              "why": f"Their gift card system runs on {name}. "
                                     f"Research that provider's known API patterns.",
                              "remediation": f"Intel: gift card backend is {name}. "
                                             f"Look up {name}'s public API docs to understand "
                                             f"the endpoints to test (authorized testing only)."}))
                ctx.publish("giftcard_providers", name)

        # 2. API endpoints: where does the gift card backend live?
        seen_eps = set()
        for pattern, key in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, all_text):
                ep = m.group(1)
                if ep in seen_eps or len(ep) > 120:
                    continue
                # skip false positives (css/js asset paths)
                if re.search(r"\.(css|png|jpg|svg|woff2?)($|\?)", ep, re.I):
                    continue
                seen_eps.add(ep)
                full = urljoin(base, ep)
                findings.append(self._f(
                    "api", "giftcard_endpoint",
                    f"Gift card endpoint: {ep}",
                    "gift card infrastructure recon",
                    source_url=full,
                    confidence=80,
                    evidence={"severity": "medium",
                              "endpoint": ep,
                              "why": "Exposed gift card API surface. Map its "
                                     "parameters and test authorization "
                                     "(authorized testing only).",
                              "remediation": f"Probe {ep} for broken object-level "
                                             f"authorization: try accessing another "
                                             f"user's gift card data. Verify auth "
                                             f"is enforced server-side."}))
                ctx.publish("endpoints", full)
                if len(seen_eps) >= 25:
                    break
            if len(seen_eps) >= 25:
                break

        # 3. Flows: purchase / redeem / balance-check / reload
        for flow, pattern, conf in FLOW_PATTERNS:
            m = re.search(pattern, all_text, re.I)
            if m:
                ctx_text = all_text[max(0, m.start() - 100):m.end() + 100]
                # try to find the form action or link nearby
                action = ""
                am = re.search(r'(?:action|href)=["\']([^"\']+)["\']',
                              ctx_text, re.I)
                if am:
                    action = am.group(1)[:120]
                findings.append(self._f(
                    "web", "giftcard_flow",
                    f"Gift card flow: {flow.replace('_', ' ')}"
                    + (f" -> {action}" if action else ""),
                    "gift card infrastructure recon",
                    confidence=conf,
                    evidence={"severity": "low",
                              "flow": flow,
                              "action": action,
                              "why": f"They have a {flow.replace('_', ' ')} flow. "
                                     f"Each flow step is a test target.",
                              "remediation": f"Map the full {flow.replace('_', ' ')} "
                                             f"flow in a browser. Test each step for "
                                             f"business-logic flaws (price tampering, "
                                             f"replay, enumeration). Authorized "
                                             f"testing only."}))

        # 4. Exposed codes (detection only - flag for the site owner)
        for key, pattern, conf in CODE_PATTERNS:
            for m in re.finditer(pattern, all_text):
                val = m.group(0)
                # skip obvious placeholders
                if re.search(r"example|placeholder|xxxx|test", val, re.I):
                    continue
                findings.append(self._f(
                    "leak", key,
                    f"Possible exposed gift card code pattern: {val[:24]}...",
                    "gift card infrastructure recon",
                    confidence=conf,
                    evidence={"severity": "high",
                              "why": "Gift card codes visible in page source. "
                                     "If real, they can be drained.",
                              "remediation": "Verify if these are real codes. "
                                             "If so, rotate them immediately and "
                                             "stop rendering codes server-side."}))
                break  # one finding per pattern type is enough

        if not findings:
            return self._ok([], "no gift card infrastructure detected")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"mapped gift card infra: {len(seen_providers)} providers, "
                       f"{len(seen_eps)} endpoints, {len(findings)} findings")
        res.duration_ms = dur
        return res
