"""Command injection detection via benign echo markers (Commix-style).

DETECTION ONLY (Tier-6 rule). The classic Commix signal, reduced to
its safest form: append a shell separator + ``echo <unique-token>``
to a parameter and check whether the token comes back in the
response. The only "command" ever run is echoing a random token the
scanner chose - no file reads, no identity commands, no output of
any real command is requested or used, no time/sleep probes.

Distinct remainder vs existing plugins (checked against master 847):
- cmdi.py detects command injection by looking for the OUTPUT of
  fixed commands (;id, |whoami -> uid=/account-name patterns) and by
  sleep canaries. A target that filters the words id/whoami or runs
  in an environment where those commands are absent is invisible to
  it. The echo-marker signal is independent: it proves the shell
  executed scanner-chosen text even when every real command is
  filtered, and it needs no timing channel.
- rce.py targets a fixed set of shell-shaped parameter names with
  sleep canaries and output-leak patterns - again no echo marker.
This plugin is only the echo-marker method.
"""
from __future__ import annotations

import time
import uuid
from typing import List
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import (fetch_baseline, fetch_homepage, param_urls,
                      probe_url, sample_urls)

REMEDIATION = ("Never pass user input to a shell. Use argument arrays "
               "instead of shell strings, strict allowlists for "
               "parameters, and prefer purpose-built libraries over "
               "os.system/exec.")

# Separator templates around the echo; {T} is the unique token.
ECHO_TEMPLATES = [
    ";echo {T}",
    "|echo {T}",
    "$(echo {T})",
    "`echo {T}`",
    "&&echo {T}",
]


class CommandInjectionDetectPlugin(Plugin):
    id = "command_injection_detect"
    label = "Command Injection (echo marker)"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Command-injection detection via a benign unique "
                   "echo marker only - no real command output, no "
                   "sleep probes.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (sends probes)")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:160]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        urls = param_urls(html, page_url, domain, ctx)

        for u in sample_urls(urls, 8):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            baseline_body, _bt = await fetch_baseline(ctx, u)
            for name, _val in params[:3]:
                token = "cmk" + uuid.uuid4().hex[:10]
                if token in baseline_body:
                    continue  # cannot happen with a fresh token; guard
                hit = False
                for tmpl in ECHO_TEMPLATES:
                    payload = tmpl.replace("{T}", token)
                    purl = probe_url(parts, params, name, payload)
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET",
                                         purl, timeout=12)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    # Discriminator: a plain reflection returns the
                    # token still glued to its payload - the word
                    # "echo" sits immediately before it (";echo cmk.."
                    # or its URL-encoded twin). Real shell execution
                    # prints the BARE token: an occurrence whose
                    # preceding characters contain no "echo" is the
                    # execution signal.
                    executed = False
                    start = 0
                    while True:
                        idx = body.find(token, start)
                        if idx < 0:
                            break
                        window = body[max(0, idx - 16):idx].lower()
                        if "echo" not in window:
                            executed = True
                            break
                        start = idx + 1
                    if executed:
                        findings.append(self._f(
                            "web", "cmdi_echo_marker",
                            f"HIGH: shell echo marker executed in "
                            f"parameter '{name}' at "
                            f"{parts.path or '/'} (payload class: "
                            f"{tmpl.split('{T}')[0]}echo <token>). The "
                            f"server ran a scanner-chosen echo, proving "
                            f"command injection.",
                            source="command-injection echo-marker probe",
                            source_url=purl, confidence=90,
                            evidence={"severity": "high",
                                      "remediation": REMEDIATION,
                                      "marker": token,
                                      "template": tmpl},
                            passive=False, bounty_value="high"))
                        hit = True
                        break
                if hit:
                    break
        res = self._ok(findings, "echo-marker probes complete")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
