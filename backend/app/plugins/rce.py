"""RCE time-based detection probe (critical findings).

Non-destructive: uses time-delay canaries (safe sleep payloads) on
parameters that commonly flow into shell commands. Measures response
time deltas; flags only when the delay matches the injected sleep.
No command output is ever retrieved. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Never pass user input to shell commands. Use argument "
               "arrays instead of shell strings, apply strict allowlists, "
               "and prefer purpose-built libraries over os.system/exec.")

RCE_PARAMS = {"cmd", "command", "exec", "run", "ping", "ip", "host",
              "domain", "q", "query", "search", "input", "data"}


class RcePlugin(Plugin):
    id = "rce"
    label = "RCE Time Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "RCE check: time-delay canary on command-like params."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:300000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
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

        SLEEP_S = 6
        tested = 0
        for u in list(urls)[:6]:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            interesting = [(n, v) for n, v in params
                           if n.lower() in RCE_PARAMS]
            if not interesting:
                continue
            for name, _v in interesting[:2]:
                # baseline timing
                try:
                    b0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", u, timeout=30)
                    base_t = time.monotonic() - b0
                except Exception:
                    continue
                tested += 1
                payload = f"test$(sleep {SLEEP_S})"
                probe = [(n, payload if n == name else v) for n, v in params]
                purl = urlunparse(parts._replace(query=urlencode(probe)))
                try:
                    p0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", purl, timeout=30)
                    delta = (time.monotonic() - p0) - base_t
                except Exception:
                    continue
                if delta >= SLEEP_S - 1.5:
                    findings.append(self._f(
                        "leak", "rce_time_based",
                        f"CRITICAL: possible command injection in parameter "
                        f"'{name}' at {parts.path or '/'}. Response delayed "
                        f"~{delta:.1f}s matching injected sleep.",
                        source="RCE time probe", source_url=purl,
                        confidence=70, passive=False,
                        evidence={"severity": "critical",
                                  "parameter": name,
                                  "delay_s": round(delta, 1),
                                  "remediation": REMEDIATION,
                                  "scope_note": "Candidate only: verify manually "
                                                "on an authorized target. "
                                                "No command output retrieved."}))
                    break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested} command-like params, "
                                 f"{len(findings)} time-based RCE candidates")
        res.duration_ms = dur
        return res
