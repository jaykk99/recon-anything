"""RCE multi-method detection probe (critical findings).

Non-destructive: uses time-delay canaries (safe sleep payloads) on
parameters that commonly flow into shell commands, plus error-based
detection looking for command output leaks. Measures response time
deltas; flags only when the delay matches the injected sleep.
No command output is ever retrieved. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import sample_urls

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


class RcePlugin(Plugin):
    id = "rce"
    label = "RCE Time Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
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
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:300000]
            page_url = str(r.url)
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

        SLEEP_S = 6
        tested = 0
        error_tested = 0
        for u in sample_urls(urls, 12):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            interesting = [(n, v) for n, v in params
                           if n.lower() in RCE_PARAMS]
            if not interesting:
                continue
            for name, _v in interesting[:2]:
                # --- Method 1: time-based canary ---
                try:
                    b0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", u, timeout=30)
                    base_t = time.monotonic() - b0
                except Exception:
                    continue
                tested += 1
                for tmpl, delay, os_label in TIME_PAYLOADS[:4]:
                    payload = tmpl.format(S=SLEEP_S)
                    probe = [(n, payload if n == name else v)
                             for n, v in params]
                    purl = urlunparse(parts._replace(query=urlencode(probe)))
                    try:
                        p0 = time.monotonic()
                        await fetch(ctx.http, ctx.limiter, "GET", purl,
                                    timeout=30)
                        delta = (time.monotonic() - p0) - base_t
                    except Exception:
                        continue
                    if delta >= SLEEP_S - 1.5:
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
                        break
                else:
                    # --- Method 2: error-based (only if time-based missed) ---
                    error_tested += 1
                    err_payload = "test; id; echo"
                    probe = [(n, err_payload if n == name else v)
                             for n, v in params]
                    purl = urlunparse(parts._replace(query=urlencode(probe)))
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                         timeout=15)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    for pat, label in ERROR_PATTERNS:
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
                            break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested} params (time) + "
                                 f"{error_tested} (error), "
                                 f"{len(findings)} RCE candidates")
        res.duration_ms = dur
        return res
