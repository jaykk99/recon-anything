"""Kiterunner-style API route discovery (Tier-3, native).

Brute-forces a curated API route wordlist (swagger-style doc paths,
versioned REST resource patterns) and decides hits by RESPONSE SHAPE,
not status alone - the Kiterunner signature. A random nonexistent
route is fingerprinted first (the SPA/HTML fallback shape); a probed
route only counts when its shape differs from that baseline: a JSON
body where the fallback is HTML, a different content type, or a
materially different size at an API status. HTML responses shaped
like the fallback are single-page-app catch-alls, not API routes.

GET only. Discovered routes are published to the discovery bus.
"""
from __future__ import annotations

import hashlib
import random
import string
import time
from typing import Dict, List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch, fetch_many
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   bounded)

# Exact doc/spec routes (swagger-style).
DOC_ROUTES = [
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/swagger-ui.html", "/swagger-ui/",
    "/v3/api-docs", "/v2/api-docs", "/redoc", "/api/openapi.json",
    "/api/swagger.json", "/.well-known/openapi.json",
]
# REST resources probed under each API base.
RESOURCES = """users user me profile accounts account auth login logout
register session sessions tokens token refresh health status metrics
ping version config settings search products product orders order
cart checkout payments payment billing invoices invoice files file
uploads upload media posts post comments messages notifications
teams members roles permissions keys webhooks events logs audit
customers items categories reports analytics jobs tasks devices
subscriptions plans coupons reviews tags articles pages widgets
backups exports imports integrations callbacks invites domains
certificates shipments addresses avatars preferences oauth sso
admin internal private public debug graphql""".split()
API_BASES = ["/api", "/api/v1", "/api/v2", "/rest", "/v1", "/v2"]
HIT_STATUSES = (200, 201, 204, 301, 302, 307, 308, 401, 403, 405)


def route_wordlist() -> List[str]:
    out: List[str] = []
    seen = set()
    for p in DOC_ROUTES:
        if p not in seen:
            seen.add(p)
            out.append(p)
    for base in API_BASES:
        out.append(base)
        seen.add(base)
        for res in RESOURCES:
            p = f"{base}/{res}"
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _shape(status: int, headers: Dict, text: str) -> Dict:
    ctype = ""
    try:
        ctype = (headers.get("content-type") or "").lower()
    except Exception:
        ctype = ""
    body = (text or "")[:4000]
    return {"status": status, "ctype": ctype,
            "is_json": "json" in ctype or body.lstrip().startswith(
                ("{", "[")),
            "is_html": "html" in ctype or body.lstrip().lower().startswith(
                ("<!doctype", "<html")),
            "length": len(text or ""),
            "hash": hashlib.sha256(body.encode("utf-8", "replace"))
            .hexdigest()[:16]}


def is_route_hit(shape: Dict, baseline: Dict) -> bool:
    """Shape-aware hit test (Kiterunner's core decision)."""
    if not shape or shape.get("status", 0) not in HIT_STATUSES:
        return False
    if not baseline:
        return True
    if shape["status"] == baseline["status"]:
        if shape["hash"] == baseline["hash"]:
            return False  # identical body = catch-all fallback
        if shape["is_html"] and baseline["is_html"]:
            # SPA fallback serves the same app shell at every route;
            # near-identical sizes mean the same shell, not a route.
            if abs(shape["length"] - baseline["length"]) <= max(
                    64, baseline["length"] * 0.05):
                return False
        if shape["is_json"] != baseline["is_json"]:
            return True  # JSON where fallback is HTML (or vice versa)
        if shape["ctype"] != baseline["ctype"]:
            return True
        return abs(shape["length"] - baseline["length"]) > max(
            256, baseline["length"] * 0.25)
    return True


class KiterunnerPlugin(Plugin):
    id = "kiterunner"
    label = "Kiterunner API Route Discovery"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "api"
    timeout_s = 120
    aggressive = True
    description = ("API route brute-force with a curated swagger/REST "
                   "wordlist and response-shape (JSON vs HTML fallback) "
                   "hit filtering.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends route probes)")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        rand = "".join(random.choices(string.ascii_lowercase, k=14))
        baseline = {"status": 0, "ctype": "", "is_json": False,
                    "is_html": False, "length": -1, "hash": ""}
        try:
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET",
                f"{base}/api/v1/__kr_{rand}__", timeout=10,
                max_retries=0, follow_redirects=False), 12)
            if r is not None:
                baseline = _shape(r.status_code, r.headers, r.text or "")
        except Exception:
            pass

        routes = route_wordlist()
        reqs = [("GET", base + quote(p, safe="/._-"),
                 {"timeout": 8, "max_retries": 0,
                  "follow_redirects": False}) for p in routes]
        results = await fetch_many(ctx.http, ctx.limiter, reqs,
                                   concurrency=6, deadline=90)
        findings: List[Finding] = []
        hits = 0
        for path, r in zip(routes, results):
            if r is None:
                continue
            shape = _shape(r.status_code, r.headers, r.text or "")
            if not is_route_hit(shape, baseline):
                continue
            url = base + path
            hits += 1
            ctx.publish("endpoints", url)
            findings.append(self._f(
                "api", "api_route", url,
                source="kiterunner route scan", source_url=url,
                confidence=75, passive=False,
                evidence={"severity": "low", "status": shape["status"],
                          "content_type": shape["ctype"],
                          "length": shape["length"],
                          "baseline_status": baseline.get("status"),
                          "remediation": "Audit this API route for "
                                         "authentication and object-"
                                         "level authorization."}))
            self._checkpoint(findings)
        res = self._ok(findings,
                       f"{len(routes)} API routes probed, {hits} "
                       f"shape-verified hits (baseline "
                       f"{baseline.get('status')})")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
