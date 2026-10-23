"""Command injection detector, broad coverage (critical findings).

Non-destructive: time-based sleep canaries (delay > 4s = signal) plus
error-based benign probes (;id, |whoami) looking for uid= leaks.
No command output is ever retrieved. Authorized testing only.

Scheduling: round-based. Cheap error-based probes sweep every URL first,
then the expensive time-based canaries run on what remains unconfirmed.
The old all-methods-per-URL order burned the budget on the first few
URLs and could miss injectable params discovered later.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Tuple
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url, sample_urls, \
    fetch_baseline, baseline_pattern_hits, over_budget

REMEDIATION = ("Never pass user input to a shell. Use argument arrays "
               "instead of shell strings, strict allowlists for params, "
               "and prefer purpose-built libraries over os.system/exec.")

# (payload, os_label) -- all payloads are benign sleep canaries
CMD_TIME_PAYLOADS: List[Tuple[str, str]] = [
    (";sleep 5 #", "linux"),
    ("|sleep 5", "linux"),
    ("`sleep 5`", "linux"),
    ("$(sleep 5)", "linux"),
    ("&& sleep 5", "linux"),
    ("%0asleep 5", "linux"),
]

# Benign error-based probes (safe commands that reveal nothing sensitive)
CMD_ERROR_PAYLOADS: List[Tuple[str, str]] = [
    (";id", "linux"),
    ("|id", "linux"),
    ("$(id)", "linux"),
    (";whoami", "linux"),
    ("|whoami", "linux"),
    ("& whoami", "windows"),
]

CMD_OUTPUT_PATTERNS = [
    (r"uid=\d+", "id output leaked"),
    (r"^root$|^www-data$|^nobody$", "whoami output leaked"),
]


class CmdInjectionPlugin(Plugin):
    id = "cmdi"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "Command Injection"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    # Time canaries are expensive (5s sleeps); give the plugin the full
    # per-plugin budget so every URL gets error-based coverage first.
    timeout_s = 120
    description = "Command injection: time-based + error-based probes."

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
            res = self._degraded(f"fetch failed: {str(e)[:120]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        sem = asyncio.Semaphore(6)
        tested = [0]
        confirmed = set()  # (url, param) already proven injectable

        # ---- Phase A: baselines for every URL (concurrent) ----
        # False-positive guard: measure the normal response time and note
        # which command-output patterns already exist in normal traffic.
        # A slow server adds latency to every request - only flag delays
        # clearly ABOVE the baseline.
        async def baseline_one(u: str):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                return None
            baseline_body, baseline_t = await fetch_baseline(ctx, u)
            baseline_cmd_hits = baseline_pattern_hits(baseline_body,
                                                      CMD_OUTPUT_PATTERNS)
            return (u, parts, params, baseline_body, baseline_t,
                    baseline_cmd_hits)

        async def baseline_sem(u: str):
            async with sem:
                return await baseline_one(u)

        items = [it for it in await asyncio.gather(
            *[baseline_sem(u) for u in sample_urls(urls, 12)]) if it]

        # ---- Method 1: error-based output leak (cheap, no sleeps) ----
        async def method_error(item, name, val):
            u, parts, params, baseline_body, baseline_t, baseline_cmd_hits = item
            for payload, os_label in CMD_ERROR_PAYLOADS:
                tested[0] += 1
                purl = probe_url(parts, params, name, val + payload)
                try:
                    pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                     timeout=15)
                    body = pr.text[:200000]
                except Exception:
                    continue
                for pat, label in CMD_OUTPUT_PATTERNS:
                    if pat in baseline_cmd_hits:
                        continue
                    if re.search(pat, body, re.I | re.M):
                        findings.append(self._f(
                            "leak", "cmdi_error_based",
                            f"CRITICAL: command injection in parameter "
                            f"'{name}' at {parts.path or '/'} "
                            f"({label}).",
                            source="cmd probe", source_url=purl,
                            confidence=80, passive=False,
                            evidence={"severity": "critical",
                                      "method": "error-based",
                                      "parameter": name,
                                      "os": os_label,
                                      "output_label": label,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Authorized testing only. "
                                                    "Benign probe only."}))
                        return True
            return False

        # ---- Method 2: time-based (expensive: 5s sleep canaries) ----
        # Queue-wait fix (2026-10-23): measure a benign CONTROL
        # back-to-back BEFORE each payload. Under a full scan the shared
        # limiter's queue backs up and plain wall-clock measurements
        # mistook queue wait for server-side delay. The control MUST
        # come first: a 5s SLEEP payload lets the queue build up behind
        # it, so a post-payload control sees a worse queue and true
        # positives get rejected.
        async def method_time(item, name, val):
            u, parts, params, baseline_body, baseline_t, baseline_cmd_hits = item
            try:
                c0 = time.monotonic()
                await fetch(ctx.http, ctx.limiter, "GET", u, timeout=20)
                control_delta = time.monotonic() - c0
            except Exception:
                control_delta = baseline_t
            for payload, os_label in CMD_TIME_PAYLOADS:
                tested[0] += 1
                purl = probe_url(parts, params, name, val + payload)
                try:
                    p0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", purl,
                                timeout=20)
                    delta = time.monotonic() - p0
                except Exception:
                    continue
                # Require absolute delay >= 4s AND >= 3s above the
                # back-to-back control.
                if delta < 4.0 or (delta - control_delta) < 3.0:
                    continue
                findings.append(self._f(
                    "leak", "cmdi_time_based",
                    f"CRITICAL: time-based command injection in "
                    f"parameter '{name}' (~{delta:.1f}s delay) at "
                    f"{parts.path or '/'}",
                    source="cmd probe", source_url=purl,
                    confidence=75, passive=False,
                    evidence={"severity": "critical",
                              "method": "time-based",
                              "parameter": name,
                              "os": os_label,
                              "delay_s": round(delta, 1),
                              "payload": payload,
                              "remediation": REMEDIATION,
                              "scope_note": "Authorized testing only. "
                                            "Sleep canary only."}))
                return True
            return False

        async def run_round(method):
            async def one(item):
                u = item[0]
                for name, val in item[2][:3]:
                    if (u, name) in confirmed:
                        continue
                    if await method(item, name, val):
                        confirmed.add((u, name))
            async def one_sem(item):
                async with sem:
                    await one(item)
            await asyncio.gather(*[one_sem(it) for it in items])
            # Checkpoint: keep confirmed findings if the runner kills us
            # on timeout mid-scan.
            self._checkpoint(findings)

        # Cheap error-based probes sweep every URL first; expensive
        # time canaries run last on whatever is still unconfirmed.
        for method in (method_error, method_time):
            if over_budget(t0, budget_s=100):
                break
            await run_round(method)

        res = self._ok(findings, f"probed {tested[0]} payloads across "
                                 f"{len(items)} URLs, {len(findings)} cmd signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
