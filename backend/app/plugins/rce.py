"""RCE multi-method detection probe (critical findings).

Non-destructive: uses time-delay canaries (safe sleep payloads) on
parameters that commonly flow into shell commands, plus error-based
detection looking for command output leaks. Measures response time
deltas; flags only when the delay matches the injected sleep.
No command output is ever retrieved. Authorized testing only.

Scheduling: round-based. The cheap error-based probe sweeps every URL
first, then the expensive 6s time canaries run on what remains. The old
all-methods-per-URL order burned the budget on the first few URLs.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import sample_urls, fetch_baseline, baseline_pattern_hits, \
    over_budget

REMEDIATION = ("Never pass user input to shell commands. Use argument "
               "arrays instead of shell strings, apply strict allowlists, "
               "and prefer purpose-built libraries over os.system/exec.")

RCE_PARAMS = {"cmd", "command", "exec", "run", "ping", "ip", "host",
              "domain", "q", "query", "search", "input", "data",
              "filename", "file", "path", "dir", "folder", "url",
              "address", "hostname", "target", "dest"}

# (payload_template, expected_delay_s, os_label)
# {S} is replaced with the sleep duration
TIME_PAYLOADS: List[Tuple[str, int, str]] = [
    ("test$(sleep {S})", 6, "linux"),
    ("test`sleep {S}`", 6, "linux"),
    ("test; sleep {S}", 6, "linux"),
    ("test|sleep {S}", 6, "linux"),
    ("test && sleep {S}", 6, "linux"),
    ("test$(sleep${IFS}{S})", 6, "linux-bypass"),
    ("test%0asleep${IFS}{S}", 6, "linux-encoded"),
]

# Error-based: command output patterns that should never appear
# from normal input reflection
ERROR_PATTERNS = [
    (r"root:.*:0:0:", "Linux /etc/passwd leak via command injection"),
    (r"uid=\d+\(.*\) gid=\d+", "id command output leak"),
    (r"Microsoft Windows \[Version", "Windows ver output leak"),
    (r"Volume in drive [A-Z]", "Windows dir output leak"),
    (r"inet addr:\d+\.\d+\.\d+\.\d+", "ifconfig output leak"),
]

SLEEP_S = 6


class RcePlugin(Plugin):
    id = "rce"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "RCE Time Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    # 6s sleep canaries are the most expensive probes in the fleet;
    # give the plugin the full per-plugin budget.
    timeout_s = 120
    description = "RCE check: time-delay canary + error-based detection."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:300000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        urls = set()
        for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', html, re.I):
            u = m.group(1)
            if u.startswith("/"):
                p = urlparse(page_url)
                u = f"{p.scheme}://{p.netloc}{u}"
            if domain in urlparse(u).netloc:
                urls.add(u)
        # chain: URLs discovered by crawler/forms/jsminer
        for eu in ctx.consume("endpoints"):
            if isinstance(eu, str) and "?" in eu and \
                    domain in urlparse(eu).netloc:
                urls.add(eu)

        sem = asyncio.Semaphore(6)
        tested = [0]
        error_tested = [0]
        confirmed = set()  # (url, param) already flagged

        # ---- Phase A: baselines for every URL (concurrent) ----
        async def baseline_one(u: str):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            interesting = [(n, v) for n, v in params
                           if n.lower() in RCE_PARAMS]
            if not interesting:
                return None
            base_body, _ = await fetch_baseline(ctx, u, timeout=15)
            base_err_hits = baseline_pattern_hits(base_body, ERROR_PATTERNS)
            return (u, parts, params, interesting, base_err_hits)

        async def baseline_sem(u: str):
            async with sem:
                return await baseline_one(u)

        items = [it for it in await asyncio.gather(
            *[baseline_sem(u) for u in sample_urls(urls, 12)]) if it]

        # ---- Method 1: error-based (cheap, one probe per param) ----
        # FP guard: these output patterns (passwd lines, uid= dumps) can
        # appear in normal content (docs, tutorials). Only flag patterns
        # ABSENT from the baseline response.
        async def method_error(item, name, val):
            u, parts, params, interesting, base_err_hits = item
            error_tested[0] += 1
            err_payload = "test; id; echo"
            probe = [(n, err_payload if n == name else v)
                     for n, v in params]
            purl = urlunparse(parts._replace(query=urlencode(probe)))
            try:
                pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                 timeout=15)
                body = pr.text[:200000]
            except Exception:
                return False
            for pat, label in ERROR_PATTERNS:
                if pat in base_err_hits:
                    continue
                if re.search(pat, body):
                    findings.append(self._f(
                        "leak", "rce_error_based",
                        f"CRITICAL: {label} in parameter '{name}' "
                        f"at {parts.path or '/'}.",
                        source="RCE error probe", source_url=purl,
                        confidence=85, passive=False,
                        evidence={"severity": "critical",
                                  "parameter": name,
                                  "indicator": label,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Authorized testing only. "
                                                "Do not exploit beyond detection."}))
                    return True
            return False

        # ---- Method 2: time-based canary (expensive: 6s sleeps) ----
        # Baseline: two normal requests. Only flag when the probe delay
        # is >=4.5s ABOVE the baseline - random slowness on a congested
        # server does not produce that.
        #
        # Queue-wait fix (2026-10-23): measure a benign CONTROL
        # back-to-back BEFORE each payload. Under a full scan the shared
        # limiter's queue backs up and plain wall-clock measurements
        # mistook queue wait for server-side delay. The control MUST
        # come first: a 6s SLEEP payload lets the queue build up behind
        # it, so a post-payload control sees a worse queue and true
        # positives get rejected.
        async def method_time(item, name, val):
            u, parts, params, interesting, base_err_hits = item
            base_samples = []
            for _ in range(2):
                try:
                    b0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", u, timeout=30)
                    base_samples.append(time.monotonic() - b0)
                except Exception:
                    pass
            if not base_samples:
                return False
            base_t = sum(base_samples) / len(base_samples)
            tested[0] += 1
            for tmpl, delay, os_label in TIME_PAYLOADS[:4]:
                payload = tmpl.format(S=SLEEP_S)
                probe = [(n, payload if n == name else v)
                         for n, v in params]
                purl = urlunparse(parts._replace(query=urlencode(probe)))
                # Fresh control BEFORE the payload (see above).
                try:
                    c0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", u, timeout=30)
                    control_delta = (time.monotonic() - c0) - base_t
                except Exception:
                    control_delta = 0.0
                try:
                    p0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", purl,
                                timeout=30)
                    delta = (time.monotonic() - p0) - base_t
                except Exception:
                    continue
                if delta < SLEEP_S - 1.5:
                    continue
                if (delta - control_delta) < SLEEP_S - 1.5:
                    continue  # queue inflation, not server sleep
                findings.append(self._f(
                    "leak", "rce_time_based",
                    f"CRITICAL: possible command injection in parameter "
                    f"'{name}' at {parts.path or '/'}. Response delayed "
                    f"~{delta:.1f}s matching injected sleep ({os_label}).",
                    source="RCE time probe", source_url=purl,
                    confidence=70, passive=False,
                    evidence={"severity": "critical",
                              "parameter": name,
                              "delay_s": round(delta, 1),
                              "os_context": os_label,
                              "remediation": REMEDIATION,
                              "scope_note": "Candidate only: verify manually "
                                            "on an authorized target. "
                                            "No command output retrieved."}))
                return True
            return False

        async def run_round(method):
            async def one(item):
                u = item[0]
                for name, _v in item[3][:2]:
                    if (u, name) in confirmed:
                        continue
                    if await method(item, name, _v):
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

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested[0]} params (time) + "
                                 f"{error_tested[0]} (error), "
                                 f"{len(findings)} RCE candidates")
        res.duration_ms = dur
        return res
