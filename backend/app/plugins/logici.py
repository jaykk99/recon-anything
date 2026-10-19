"""API logic injection detector (medium findings).

Non-destructive, differential method: send boolean/type-juggling
variants (true, 1, [], {}, null, 0, "true") for each param and
compare against a baseline response. Status code or body length
drift between baseline and type-juggled probes is a logic-flaw
signal (loose comparison, mass assignment, type confusion).
No privileged actions are attempted. Authorized testing only.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url, sample_urls, \
    over_budget

REMEDIATION = ("Validate and cast every input to its declared type "
               "server-side. Use strict comparisons, reject unexpected "
               "types, and never trust client-supplied booleans or "
               "arrays in authorization logic.")

# Type-juggling / boolean probe values
LOGIC_PROBES = [
    "true",
    "false",
    "1",
    "0",
    "[]",
    "{}",
    "null",
    "\"true\"",
    "\"1\"",
]

# A type-juggled response must differ from the baseline by at least 40%
# in length (or flip status) to count. Lower than that is normal page
# variance; sqli's boolean-blind gate uses 50% for the same reason.
DRIFT_RATIO = 0.4
# Two baseline fetches must agree within 15% or the page is dynamic
# (timestamps, CSRF tokens, ads) and any drift is meaningless.
BASELINE_STABILITY = 0.15


class LogicInjectionPlugin(Plugin):
    id = "logici"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "API Logic Injection"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "api"
    description = "Logic injection: boolean/type-juggle differential probes."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        tested = 0
        for u in sample_urls(urls, 8):
            if over_budget(t0):
                break
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            # Baseline: fetch the original URL TWICE. If the two baselines
            # already differ by >15%, the page has dynamic content and any
            # true/false diff is meaningless - skip to avoid FPs.
            try:
                br1 = await fetch(ctx.http, ctx.limiter, "GET", u, timeout=15)
                br2 = await fetch(ctx.http, ctx.limiter, "GET", u, timeout=15)
                b1_len, b2_len = len(br1.text), len(br2.text)
                if b1_len == 0:
                    continue
                if b2_len > 0 and abs(b1_len - b2_len) / max(b1_len, b2_len) \
                        > BASELINE_STABILITY:
                    continue  # dynamic page - drift test unreliable
                base_status = br1.status_code
                base_len = b1_len
            except Exception:
                continue

            async def probe_drift(name: str, pv: str):
                """(status_drift, len_drift_ratio) of one probe vs baseline."""
                purl = probe_url(parts, params, name, pv)
                pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                 timeout=15)
                p_len = len(pr.text)
                return (pr.status_code != base_status,
                        abs(p_len - base_len) / max(base_len, 1),
                        pr.status_code, p_len)

            for name, val in params[:3]:
                found = False
                for pv in LOGIC_PROBES:
                    if over_budget(t0):
                        break
                    tested += 1
                    try:
                        sd, ld, pstat, plen = await probe_drift(name, pv)
                    except Exception:
                        continue
                    drifted = sd or ld > DRIFT_RATIO
                    if not drifted:
                        continue
                    # Confirmation: a single drifting probe is weak (search
                    # pages drift when the query changes). Send a SECOND,
                    # distinct probe value - only flag when BOTH drift the
                    # same way (status flip, or length drift in the same
                    # direction).
                    pv2 = "null" if pv != "null" else "true"
                    try:
                        sd2, ld2, pstat2, plen2 = await probe_drift(name, pv2)
                        tested += 1
                    except Exception:
                        continue
                    both_status = sd and sd2 and pstat == pstat2
                    same_dir = ((plen > base_len) == (plen2 > base_len))
                    both_len = ld > DRIFT_RATIO and ld2 > DRIFT_RATIO \
                        and same_dir
                    if both_status or both_len:
                        drift = f"status {base_status}->{pstat}" \
                            if both_status else \
                            f"length drift {ld:.0%}/{ld2:.0%}"
                        findings.append(self._f(
                            "api", "logic_injection",
                            f"MEDIUM: possible logic injection in parameter "
                            f"'{name}' at {parts.path or '/'} "
                            f"(type-juggled values caused {drift} vs "
                            f"baseline, confirmed with 2 probe values).",
                            source="logic probe",
                            source_url=probe_url(parts, params, name, pv),
                            confidence=65, passive=False,
                            evidence={"severity": "medium",
                                      "method": "differential",
                                      "parameter": name,
                                      "probe_values": [pv, pv2],
                                      "baseline_status": base_status,
                                      "probe_status": pstat,
                                      "baseline_len": base_len,
                                      "probe_len": plen,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Candidate: verify manually. "
                                                    "Authorized testing only."}))
                        found = True
                        break
                if found:
                    continue

        res = self._ok(findings, f"probed {tested} values across "
                                 f"{len(urls)} URLs, {len(findings)} logic signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
