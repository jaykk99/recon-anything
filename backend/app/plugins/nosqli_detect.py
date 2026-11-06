"""NoSQL injection detection on JSON request bodies (NoSQLMap-style).

DETECTION ONLY (Tier-6 rule). Modern NoSQL injection lives in JSON
APIs, so this plugin speaks JSON: for each candidate API endpoint it
sends a typed baseline body and an operator-shaped body of the
benign class ({"$ne": null} - "not equal to null", which matches
documents without extracting anything) and compares the responses.
A verdict needs a STABLE baseline (the same baseline sent twice
must agree) plus a material differential on the operator body:
status change, JSON key-set change, or a large length change - or a
NoSQL error signature that only the operator body produces. No
document is ever requested back beyond what the endpoint normally
returns, nothing is extracted, no $where code is sent (the existing
nosqli plugin owns the GET/$where surface).

Distinct remainder vs existing plugins (checked against master 847):
nosqli.py works only on GET query parameters (operator strings as
param values, error text, $where sleep canary) - it never sends a
JSON body. JSON-body operator differentials on API endpoints are
uncovered there and are this plugin's whole scope.
"""
from __future__ import annotations

import json
import re
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage

REMEDIATION = ("Never pass raw request JSON into a query. Build "
               "queries from explicitly typed fields, reject operator "
               "keys ($-prefixed) in user input, and validate types "
               "at the API boundary (schema validation).")

NOSQL_ERRORS = [
    (r"MongoError|MongoServerError", "MongoDB error"),
    (r"Cast to .*? failed", "Mongoose cast error"),
    (r"BSON.*?error|BSONError", "BSON error"),
    (r"unknown operator", "unknown-operator error"),
]

MAX_ENDPOINTS = 5
LENGTH_DELTA = 0.40

# Candidate API paths harvested from the homepage (links/scripts).
_API_LINK_RX = re.compile(r"""["'(](/api/[\w\-./]*|/v\d+/[\w\-./]*)["')]""")


def _endpoints(ctx: Ctx, html: str, page_url: str) -> List[str]:
    out: List[str] = []
    for item in ctx.consume("endpoints"):
        s = str(item)
        if "/api/" in s or "/v1/" in s or "/v2/" in s:
            if s not in out:
                out.append(s)
    for m in _API_LINK_RX.finditer(html or ""):
        u = urljoin(page_url, m.group(1))
        if u not in out:
            out.append(u)
    return out[:MAX_ENDPOINTS]


def _shape(status: int, text: str) -> Dict:
    keys: Set[str] = set()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            keys = set(data.keys())
        elif isinstance(data, list) and data and \
                isinstance(data[0], dict):
            keys = set(data[0].keys())
    except Exception:
        pass
    return {"status": status, "length": len(text or ""), "keys": keys}


def _material_diff(a: Dict, b: Dict) -> Optional[str]:
    if a["status"] != b["status"] and 0 not in (a["status"],
                                                b["status"]):
        return f"status {a['status']} -> {b['status']}"
    if a["keys"] and b["keys"] and a["keys"] != b["keys"]:
        return (f"JSON keys {sorted(a['keys'])[:6]} -> "
                f"{sorted(b['keys'])[:6]}")
    la, lb = a["length"], b["length"]
    if max(la, lb) >= 40 and abs(la - lb) > LENGTH_DELTA * max(la, lb):
        return f"length {la} -> {lb}"
    return None


class NosqliDetectPlugin(Plugin):
    id = "nosqli_detect"
    label = "NoSQL Injection (JSON body)"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "api"
    description = ("NoSQL injection detection for JSON APIs: benign "
                   "operator-body differential vs a verified-stable "
                   "baseline. No extraction, no $where.")

    async def _post(self, ctx: Ctx, url: str, body: Dict):
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url,
                            json=body, timeout=12, max_retries=0)
            return r.status_code, r.text[:100000]
        except Exception:
            return 0, ""

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (sends JSON "
                                 "probes)")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:160]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        endpoints = _endpoints(ctx, html, page_url)

        baseline_body = {"id": "1", "probe": "recon-baseline"}
        operator_bodies = [
            {"id": {"$ne": None}, "probe": "recon-baseline"},
            {"id": {"$ne": "1"}, "probe": "recon-baseline"},
        ]
        for url in endpoints:
            s1, t1 = await self._post(ctx, url, baseline_body)
            s2, t2 = await self._post(ctx, url, baseline_body)
            if s1 == 0:
                continue
            base_shape = _shape(s1, t1)
            if _material_diff(base_shape, _shape(s2, t2)):
                continue  # unstable baseline: no honest verdict here
            baseline_errs = {lbl for pat, lbl in NOSQL_ERRORS
                             if re.search(pat, t1, re.I)}
            verdict = None
            for op_body in operator_bodies:
                so, to = await self._post(ctx, url, op_body)
                if so == 0:
                    continue
                diff = _material_diff(base_shape, _shape(so, to))
                if diff:
                    verdict = (f"operator body {json.dumps(op_body)} "
                               f"changed the response ({diff}) vs the "
                               f"stable typed baseline")
                    break
                new_errs = {lbl for pat, lbl in NOSQL_ERRORS
                            if re.search(pat, to, re.I)} - baseline_errs
                if new_errs:
                    verdict = (f"operator body produced a NoSQL "
                               f"error signature ({sorted(new_errs)[0]})"
                               f" absent from the baseline")
                    break
            if verdict:
                findings.append(self._f(
                    "api", "nosqli_json_differential",
                    f"HIGH: NoSQL operator injection signal at "
                    f"{urlparse(url).path}: {verdict}. The endpoint "
                    f"appears to pass request JSON operators into a "
                    f"query.",
                    source="nosql json differential probe",
                    source_url=url, confidence=75,
                    evidence={"severity": "high",
                              "remediation": REMEDIATION,
                              "verdict": verdict},
                    passive=False, bounty_value="high"))

        res = self._ok(findings,
                       f"JSON differential checks on "
                       f"{len(endpoints)} endpoints")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
