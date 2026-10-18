"""HTTP request smuggling / desync detection plugin.

Non-destructive timing-based probes only. Sends tiny HARMLESS payloads
with conflicting Content-Length / Transfer-Encoding headers (CL.TE,
TE.CL, TE.TE variants) and compares response timing against a clean
baseline. A large, consistent timing anomaly suggests the front-end and
back-end disagree on where the request ends (desync). It never sends a
smuggled second request, never poisons a connection, and never acts on
a response as if smuggling worked.
"""
from __future__ import annotations

import statistics
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

HARMLESS = b"recon-desync-probe"


class SmugglingPlugin(Plugin):
    id = "smuggling"
    label = "Request Smuggling Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Timing-based HTTP request-smuggling/desync detection "
                   "with harmless conflicting-header probes.")
    phase = 2
    timeout_s = 150

    async def _timed_post(self, ctx: Ctx, url: str, *,
                          headers: Dict[str, str],
                          timeout: int = 8) -> Tuple[Optional[int], Optional[float], str]:
        """POST with custom headers; returns (status, elapsed_s, note).

        Single attempt (no retries): a server that honors a bogus
        Content-Length will hold the connection until the timeout, and
        that delay IS the signal we are measuring.
        """
        t0 = time.monotonic()
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url, timeout=timeout,
                            max_retries=0, follow_redirects=False,
                            content=HARMLESS, headers=headers)
            return r.status_code, time.monotonic() - t0, ""
        except Exception as e:
            name = type(e).__name__
            return None, time.monotonic() - t0, name

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        url = base + "/"

        findings: List[Finding] = []

        # --- baseline: two clean small POSTs --------------------------------
        baseline: List[float] = []
        for _ in range(2):
            st, el, _ = await self._timed_post(ctx, url, headers={})
            if el is not None:
                baseline.append(el)
        base_med = statistics.median(baseline) if baseline else 1.0
        threshold = max(base_med * 2.5, base_med + 4.0, 4.0)

        async def check(variant: str, hdrs: Dict[str, str], desc: str,
                        conf: int) -> None:
            """Flag a timing anomaly as a *possible* desync.

            A slow conflicting-header probe means the server accepted an
            ambiguous request and honored one framing over the other -
            the precondition for desync. It is reported as possible
            (theoretical) with manual confirmation in the remediation,
            never as confirmed smuggling.
            """
            st, el, note = await self._timed_post(ctx, url, headers=hdrs)
            if el is not None and el > threshold:
                findings.append(self._f(
                    "web", f"smuggling_{variant}",
                    f"Possible {variant} desync: {desc} took {el:.1f}s vs "
                    f"{base_med:.1f}s baseline "
                    f"(status={st}, {note or 'completed'})",
                    source="Request smuggling detector", source_url=url,
                    confidence=conf, passive=False,
                    evidence={
                        "severity": "medium", "exploitability": "theoretical",
                        "remediation": (
                            "Normalize ambiguous requests at the front-end: "
                            "reject requests carrying both Content-Length and "
                            "Transfer-Encoding, or duplicate/obfuscated TE "
                            "headers. Keep front/back HTTP parsers in sync, "
                            "and have the app team confirm with a manual "
                            f"desync test before treating this {variant} "
                            "signal as exploitable.")}))

        # --- CL.TE: front uses CL, back uses TE -------------------------------
        # TE: chunked with a real chunked body; CL smaller than the body.
        await check("cl_te",
                    {"Content-Length": "4", "Transfer-Encoding": "chunked"},
                    "conflicting CL(4)/TE:chunked probe", 60)

        # --- TE.CL: front uses TE, back uses CL --------------------------------
        # CL claims far more than is sent; a CL-honoring server waits.
        await check("te_cl",
                    {"Content-Length": "100000", "Transfer-Encoding": "chunked"},
                    "CL(100000)/TE:chunked probe", 60)

        # --- TE.TE: duplicate Transfer-Encoding ---------------------------------
        await check("te_te",
                    {"Transfer-Encoding": "chunked, chunked"},
                    "duplicate Transfer-Encoding probe", 55)

        # Healthy behavior note: server that rejects ambiguous requests.
        if not findings:
            findings.append(self._f(
                "web", "smuggling_clean",
                f"No desync timing anomalies: CL.TE / TE.CL / TE.TE probes "
                f"all responded within normal bounds of the {base_med:.1f}s "
                "baseline",
                source="Request smuggling detector", source_url=url,
                confidence=70, passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": "No action needed. Keep rejecting "
                          "ambiguous CL/TE requests at the edge."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"baseline {base_med:.1f}s; 3 desync probes")
        res.duration_ms = dur
        return res
