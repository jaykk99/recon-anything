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
    # The runner hard-kills plugins at 30s (MAX_PLUGIN_TIMEOUT_S). This
    # plugin's timing probes are slow by design, so the whole probe
    # sequence is budgeted: 1 baseline + 3 variant probes with tight
    # timeouts, sequential (timing signals must not interfere).
    timeout_s = 30

    async def _timed_post(self, ctx: Ctx, url: str, *,
                          headers: Dict[str, str],
                          timeout: int = 8) -> Tuple[Optional[int], Optional[float], str]:
        """POST with custom headers; returns (status, elapsed_s, note).

        Single attempt (no retries): a server that honors a bogus
        Content-Length will hold the connection until the timeout, and
        that delay IS the signal we are measuring.

        Connection: close is forced: a timed-out probe leaves the pooled
        connection in a dirty state (the server is still waiting for the
        declared body), and the NEXT probe on that pooled connection
        dies instantly with LocalProtocolError - which would corrupt the
        control-probe comparison.
        """
        t0 = time.monotonic()
        hdrs = dict(headers or {})
        hdrs.setdefault("Connection", "close")
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url, timeout=timeout,
                            max_retries=0, follow_redirects=False,
                            content=HARMLESS, headers=hdrs)
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

        # --- baseline: one clean small POST --------------------------------
        # Single baseline keeps the whole probe sequence inside the 30s
        # budget (probes below can hold the connection for seconds each).
        bstatus, bel, _ = await self._timed_post(ctx, url, headers={},
                                                 timeout=5)
        base_med = bel if bel is not None else 1.0
        # A desync candidate must be >4s above the baseline. Anything less
        # is normal jitter on a shared front-end.
        threshold = max(base_med * 2.5, base_med + 4.0, 4.0)

        async def check(variant: str, hdrs: Dict[str, str], desc: str,
                        conf: int) -> None:
            """Flag a timing anomaly as a *possible* desync.

            A slow conflicting-header probe means the server accepted an
            ambiguous request and honored one framing over the other -
            the precondition for desync. It is reported as possible
            (theoretical) with manual confirmation in the remediation,
            never as confirmed smuggling.

            FP note on the TE.CL probe: it only fires when the server
            actually WAITS >4s on the contradictory framing. Per
            RFC 9112 a server MUST ignore Content-Length when
            Transfer-Encoding is present, so waiting on the bogus CL is
            genuinely anomalous - the exact ambiguity TE.CL desyncs
            need. RFC-compliant servers answer fast and never flag.
            """
            st, el, note = await self._timed_post(ctx, url, headers=hdrs,
                                                  timeout=5)
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
        # CL claims far more than is sent; a server that honors the bogus
        # CL over TE waits (RFC 9112 says TE wins - waiting is anomalous).
        await check("te_cl",
                    {"Content-Length": "100000", "Transfer-Encoding": "chunked"},
                    "CL(100000)/TE:chunked probe", 60)

        # --- TE.TE: duplicate Transfer-Encoding ---------------------------------
        await check("te_te",
                    {"Transfer-Encoding": "chunked, chunked"},
                    "duplicate Transfer-Encoding probe", 55)

        dur = int((time.monotonic() - t0) * 1000)
        note = f"baseline {base_med:.1f}s; 3 desync probes"
        if not findings:
            note += " - no desync timing anomalies"
        res = self._ok(findings, note)
        res.duration_ms = dur
        return res
