"""CORS misconfiguration tester plugin.

Tests CORS with multiple origins including null, subdomains, and
trusted-domain bypasses. More thorough than a single-origin check.
Custom-built, no API keys needed.
"""
from __future__ import annotations

import asyncio

import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class CorsPlugin(Plugin):
    id = "cors"
    label = "CORS Tester"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Deep CORS misconfiguration testing."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = await web_base(ctx, target, domain)
        findings: List[Finding] = []

        test_origins = [
            "https://evil.com",
            "null",
            f"https://{domain}.evil.com",
            f"https://evil{domain}",
            f"https://{domain}.attacker.com",
        ]

        _cors_sem = asyncio.Semaphore(5)
        _responded = [0]  # probes that got any HTTP response (vs network failure)

        async def _cors_probe(origin: str):
            async with _cors_sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                                    headers={"Origin": origin})
                except Exception:
                    return None
            _responded[0] += 1
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()

            if acao == origin:
                severity = "CRITICAL" if acac == "true" else "HIGH"
                return self._f(
                    "web", "cors_reflect",
                    f"{severity}: CORS reflects origin '{origin}'" +
                    (" with credentials=true - full account takeover possible" if acac == "true" else ""),
                    source="CORS tester", source_url=url,
                    confidence=90, passive=True)
            elif acao == "*":
                return self._f(
                    "web", "cors_wildcard",
                    f"CORS allows any origin (*) for '{origin}'" +
                    (" with credentials - misconfigured" if acac == "true" else " (no credentials, lower risk)"),
                    source="CORS tester", source_url=url,
                    confidence=75 if acac == "true" else 50, passive=True)
            return None

        for _f in await asyncio.gather(*[_cors_probe(o) for o in test_origins]):
            if _f:
                findings.append(_f)

        # Preflight check
        try:
            r = await fetch(ctx.http, ctx.limiter, "OPTIONS", url, timeout=10,
                            headers={
                                "Origin": "https://evil.com",
                                "Access-Control-Request-Method": "PUT",
                                "Access-Control-Request-Headers": "X-Custom",
                            })
            acam = r.headers.get("access-control-allow-methods", "")
            if "PUT" in acam or "DELETE" in acam:
                findings.append(self._f(
                    "web", "cors_methods",
                    f"CORS preflight allows dangerous methods: {acam}",
                    source="CORS tester", source_url=url,
                    confidence=70, passive=True))
        except Exception:
            pass

        if not findings:
            if _responded[0] == 0:
                # No probe got a response: claiming "properly configured"
                # would be a false negative. Degrade instead.
                res = self._degraded("no CORS probe received a response; "
                                     "CORS posture unknown")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            findings.append(self._f(
                "web", "cors_ok",
                f"CORS properly configured - no misconfigurations in {len(test_origins)} origin tests",
                source="CORS tester", source_url=url,
                confidence=70, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"tested {len(test_origins)} origins")
        res.duration_ms = dur
        return res
