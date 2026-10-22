"""Hidden GET parameter discovery + reflection testing (GET only).

Takes the site's discovered URLs (homepage links, crawler endpoints) and
tests a curated list of commonly-hidden parameter names on each page.
For every candidate it sends ONE inert canary value and reports:
  - param_accepted: the page behaved differently vs baseline (param exists)
  - param_reflected: the canary is reflected unencoded (XSS candidate)

GET only, inert canaries, no exploitation. Rate-limited.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from typing import Dict, List, Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# commonly-hidden / debug / legacy parameter names
PARAM_WORDLIST = """id user userid username name q query querystring search
keyword kw s term text title content msg message comment email mail
page p action do act view op cmd command exec run file path filename
filepath include template page_id lang language theme skin sort order
by dir filter cat category product item article pid sid uid cid mid
ref referer referrer source utm_source campaign redirect next return
url dest destination target continue callback jsonp format output
type view2 layout tmpl debug test dev verbose trace token key apikey
api_key secret auth session sid2 sid_ sessionid sidtoken
limit offset page_num per_page count size width height w h x y lat
lon long latitude longitude zoom radius distance price min max from
to start end date day month year time datetime coupon promo discount
code voucher giftcard card number account acct invoice order cart
address city state zip country phone mobile fax company org title2
firstname lastname fname lname nick handle avatar image img pic photo
thumb file2 doc document download attachment preview thumb2
redirect_url return_url next_url continue_url callback_url
""".split()


class ParamDiscoveryPlugin(Plugin):
    id = "param_discovery"
    label = "Parameter Discovery"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 240
    # Phase 2: runs after apidiscover (phase 1) so the api_chain can feed
    # it discovered API base paths via the "endpoints" bus.
    phase = 2
    description = ("Discover hidden GET params with canary probes; flag "
                   "unencoded reflection (XSS candidates). GET only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")

        # seed URLs: homepage + crawler-discovered endpoints (param-less pages)
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:300000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        seeds: Set[str] = {page_url.split("?")[0]}
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
            u = m.group(1)
            if u.startswith("/"):
                p = urlparse(page_url)
                u = f"{p.scheme}://{p.netloc}{u}"
            pu = urlparse(u)
            if pu.scheme in ("http", "https") and domain in pu.netloc:
                seeds.add(f"{pu.scheme}://{pu.netloc}{pu.path}")
        for eu in ctx.consume("endpoints"):
            if isinstance(eu, str):
                pu = urlparse(eu)
                if domain in pu.netloc:
                    seeds.add(f"{pu.scheme}://{pu.netloc}{pu.path}".rstrip("?"))
        # Chain: api_base signals from the api_chain (apidiscover phase 1 ->
        # param_discovery phase 2) seed the discovered API base paths too.
        try:
            from ..chains import chain_signals
            for ab in chain_signals(ctx, "api_base"):
                pu = urlparse(ab)
                if domain in pu.netloc:
                    seeds.add(f"{pu.scheme}://{pu.netloc}{pu.path}".rstrip("?"))
        except Exception:
            pass

        # params already known from links/forms: skip re-testing those
        known_params: Set[str] = set()
        for m in re.finditer(r"[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=", html):
            known_params.add(m.group(1).lower())

        candidates = [p for p in PARAM_WORDLIST if p not in known_params]

        sem = asyncio.Semaphore(6)
        tested = [0]

        async def test_seed(seed: str):
            # baseline: plain page
            try:
                b = await fetch(ctx.http, ctx.limiter, "GET", seed,
                                timeout=15, max_retries=1)
                base_body = b.text[:60000]
                base_len = len(base_body)
            except Exception:
                return
            parts = urlparse(seed)
            for pname in candidates:
                canary = "pd" + uuid.uuid4().hex[:10]
                q = [(pname, canary)]
                purl = urlunparse(parts._replace(query=urlencode(q)))
                tested[0] += 1
                try:
                    async with sem:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                         timeout=15, max_retries=1)
                    body = pr.text[:60000]
                except Exception:
                    continue
                if canary in body and f"&lt;{canary}" not in body \
                        and f"&gt;{canary}" not in body:
                    # crude context check: raw reflection?
                    findings.append(self._f(
                        "web", "param_reflected",
                        f"HIGH: hidden parameter '{pname}' reflects input "
                        f"unencoded at {parts.path or '/'} - XSS candidate",
                        source="param discovery", source_url=purl,
                        confidence=70, passive=False,
                        evidence={"severity": "high",
                                  "parameter": pname,
                                  "remediation": ("Encode all reflected input "
                                                  "for its output context; "
                                                  "remove the parameter if "
                                                  "unused.")}))
                    continue
                # accepted but not reflected: significant behavior change?
                if abs(len(body) - base_len) > max(500, base_len * 0.25):
                    findings.append(self._f(
                        "web", "param_accepted",
                        f"MEDIUM: hidden parameter '{pname}' changes "
                        f"response at {parts.path or '/'} "
                        f"({base_len}->{len(body)} bytes)",
                        source="param discovery", source_url=purl,
                        confidence=55, passive=False,
                        evidence={"severity": "medium",
                                  "parameter": pname,
                                  "remediation": ("Inventory this parameter: "
                                                  "document it, validate it "
                                                  "server-side, remove if "
                                                  "dead code.")}))

        # Dynamic-looking pages first (.php/.aspx): hidden params live
        # on dynamic pages, not static assets. Cap keeps runtime bounded.
        ordered = sorted(seeds,
                         key=lambda s: (0 if re.search(r"\.(php|aspx?|jsp|cgi)",
                                                       urlparse(s).path, re.I)
                                        else 1, s))[:10]
        for s in ordered:
            await test_seed(s)
            # Checkpoint: keep confirmed findings if the runner kills us
            # on timeout mid-sweep.
            self._checkpoint(findings)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"tested {tested[0]} param probes on "
                       f"{len(ordered)} pages, {len(findings)} hits")
        res.duration_ms = dur
        return res
