"""Command injection detector, broad coverage (critical findings).

Non-destructive: time-based sleep canaries (delay > 4s = signal) plus
error-based benign probes (;id, |whoami) looking for uid= leaks.
No command output is ever retrieved. Authorized testing only.
"""
from __future__ import annotations

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
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        tested = 0
        for u in sample_urls(urls, 12):
            if over_budget(t0):
                break
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue

            # --- Baseline timing ---
            # False-positive guard: measure the normal response time first.
            # A slow server or congested network adds latency to every
            # request - only flag delays clearly ABOVE the baseline.
            baseline_body, baseline_t = await fetch_baseline(ctx, u)
            # Which error patterns already exist in normal traffic?
            baseline_cmd_hits = baseline_pattern_hits(baseline_body,
                                                      CMD_OUTPUT_PATTERNS)

            for name, val in params[:3]:
                found = False

                # --- Method 1: time-based ---
                for payload, os_label in CMD_TIME_PAYLOADS:
                    tested += 1
                    purl = probe_url(parts, params, name, val + payload)
                    try:
                        p0 = time.monotonic()
                        await fetch(ctx.http, ctx.limiter, "GET", purl,
                                    timeout=20)
                        delta = time.monotonic() - p0
                    except Exception:
                        continue
                    # Require absolute delay >= 4s AND >= 3s above baseline.
                    if delta >= 4.0 and (delta - baseline_t) >= 3.0:
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
                        found = True
                        break
                if found:
                    continue

                # --- Method 2: error-based output leak ---
                for payload, os_label in CMD_ERROR_PAYLOADS:
                    tested += 1
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
                                          "payload": payload,
                                          "remediation": REMEDIATION,
                                          "scope_note": "Authorized testing only. "
                                                        "Benign probe only."}))
                            found = True
                            break
                    if found:
                        break
            # Checkpoint: keep confirmed findings if the runner kills us
            # on timeout mid-scan.
            self._checkpoint(findings)

        res = self._ok(findings, f"probed {tested} payloads across "
                                 f"{len(urls)} URLs, {len(findings)} cmd signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
