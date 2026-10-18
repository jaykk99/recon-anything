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
from .injutil import fetch_homepage, param_urls, probe_url

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

DRIFT_RATIO = 0.25


class LogicInjectionPlugin(Plugin):
    id = "logici"
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
        for u in list(urls)[:8]:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            # Baseline: original URL untouched
            try:
                br = await fetch(ctx.http, ctx.limiter, "GET", u, timeout=15)
                base_status = br.status_code
                base_len = len(br.text)
            except Exception:
                continue
            if base_len == 0:
                continue
            for name, val in params[:3]:
                found = False
                for pv in LOGIC_PROBES:
                    tested += 1
                    purl = probe_url(parts, params, name, pv)
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                         timeout=15)
                    except Exception:
                        continue
                    p_len = len(pr.text)
                    status_drift = pr.status_code != base_status
                    len_drift = abs(p_len - base_len) / max(base_len, 1)
                    if status_drift or len_drift > DRIFT_RATIO:
                        drift = f"status {base_status}->{pr.status_code}" \
                            if status_drift else \
                            f"length drift {len_drift:.0%}"
                        findings.append(self._f(
                            "api", "logic_injection",
                            f"MEDIUM: possible logic injection in parameter "
                            f"'{name}' at {parts.path or '/'} "
                            f"(value '{pv}' caused {drift} vs baseline).",
                            source="logic probe", source_url=purl,
                            confidence=60, passive=False,
                            evidence={"severity": "medium",
                                      "method": "differential",
                                      "parameter": name,
                                      "probe_value": pv,
                                      "baseline_status": base_status,
                                      "probe_status": pr.status_code,
                                      "baseline_len": base_len,
                                      "probe_len": p_len,
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
