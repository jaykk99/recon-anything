"""Arjun-style hidden parameter discovery via response differentials.

param_discovery.py already answers "does this parameter exist / does
it reflect" with batched canaries. This plugin asks the Arjun
question instead: WHICH parameters change the application's
behaviour, and what does the shape of that change suggest?

Method (GET only, benign markers only):
1. Baseline signature per seed endpoint: status, body length, word
   count, and whether the body carries a database error signature.
2. Differential bisection: the whole parameter wordlist rides on one
   request, each parameter with its own inert canary value. If the
   response signature differs from baseline, the set is bisected
   until the behaviour-changing parameters are named individually.
3. Error bisection: the same bisection, but every canary carries a
   single trailing quote (') and the predicate is "a database error
   signature appeared that the baseline does not have". That is a
   SQLi SUSPECT marker only - no UNION, no stacked queries, no
   extraction, ever.
4. Classification: an id-shaped parameter (id, user_id, order_id...)
   that changes behaviour is an IDOR SUSPECT marker; a parameter
   whose quote variant flips the error signature is a SQLi SUSPECT
   marker; anything else is a plain hidden-parameter behaviour note.
   Suspects are leads for manual verification, not confirmations.

Rate-limited via ctx.probe (shared cache/limiter), hard probe cap.
Phase 2: seeds come from the discovery bus, falling back to the
homepage.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain

PARAMS = """id user_id uid account account_id customer_id order_id
product_id file_id page_id post_id item_id category_id id2 user
account order product file path url redirect next return callback
q query search keyword term page limit offset sort order_by filter
category type action cmd name email token key api_key debug test
admin role lang locale format data input value ref source target
dest view template include dir document site code state mode""".split()

ID_LIKE = re.compile(r"(?i)(^id$|_id$|^uid$|user|account|customer|"
                     r"order|product|file|invoice|member|client)")
DB_ERRORS = ("sql syntax", "mysql", "mariadb", "postgresql", "psql",
             "ora-0", "sqlite", "sqlstate", "odbc", "syntax error in",
             "unclosed quotation", "microsoft ole db")
MAX_SEEDS = 3
MAX_PROBES = 110


def _signature(resp: Optional[Dict]) -> Tuple[int, int, int, bool]:
    if not resp:
        return (0, 0, 0, False)
    text = (resp.get("text") or "").lower()
    return (int(resp.get("status") or 0),
            int(resp.get("length") or 0),
            len(re.findall(r"\S+", text)),
            any(e in text for e in DB_ERRORS))


def _differs(a: Tuple, b: Tuple) -> bool:
    if a[0] != b[0]:
        return True
    if abs(a[1] - b[1]) > max(24, int(b[1] * 0.02)):
        return True
    if abs(a[2] - b[2]) > 3:
        return True
    return False


class ParamDiscoveryArjunPlugin(Plugin):
    id = "param_discovery_arjun"
    label = "Hidden Parameter Differentials (Arjun-style)"
    accepts = ["domain", "url"]
    passive = False
    aggressive = True
    cost = Cost.FREE
    group = "api"
    phase = 2
    timeout_s = 120
    description = ("Finds hidden GET parameters whose presence changes "
                   "the response (length/status/error differential, "
                   "bisected Arjun-style) and flags id-shaped params "
                   "as IDOR suspects and quote-sensitive params as "
                   "SQLi suspects. Benign canary markers only.")

    async def _seeds(self, ctx: Ctx, base: str, domain: str) -> List[str]:
        seeds: List[str] = []
        for eu in ctx.consume("endpoints"):
            if isinstance(eu, str) and same_domain(eu, domain):
                pu = urlparse(eu)
                seeds.append(
                    f"{pu.scheme}://{pu.netloc}{pu.path}".rstrip("?"))
        page = await ctx.fetch_page(base)
        if page:
            html = page.get("text") or ""
            root = urlparse(base)
            for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
                u = m.group(1)
                if u.startswith("/"):
                    u = f"{root.scheme}://{root.netloc}{u}"
                if same_domain(u, domain):
                    pu = urlparse(u)
                    seeds.append(
                        f"{pu.scheme}://{pu.netloc}{pu.path}".rstrip("?"))
        out, seen = [], set()
        for s in seeds:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out[:MAX_SEEDS] or [base]

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        start = time.time()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "parameter differentials send probes; "
                                "needs active mode")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        base = await web_base(ctx, target, domain)
        budget = [MAX_PROBES]
        canary = "arj" + uuid.uuid4().hex[:8]

        async def probe(url: str) -> Optional[Dict]:
            if budget[0] <= 0:
                return None
            budget[0] -= 1
            return await ctx.probe(url, timeout=8)

        def build(seed: str, params: List[str], quote: bool) -> str:
            parts = urlparse(seed)
            q = [(p, f"{canary}{i}" + ("'" if quote else ""))
                 for i, p in enumerate(params)]
            return urlunparse(parts._replace(query=urlencode(q)))

        async def bisect(seed: str, params: List[str],
                         predicate: Callable[[Optional[Dict]], bool]
                         ) -> List[str]:
            """Name the individual params satisfying predicate."""
            if not params:
                return []
            resp = await probe(build(seed, params, quote=False)
                               if predicate.__name__ == "diff_pred"
                               else build(seed, params, quote=True))
            if not predicate(resp):
                return []
            if len(params) == 1:
                return params
            mid = len(params) // 2
            left = await bisect(seed, params[:mid], predicate)
            right = await bisect(seed, params[mid:], predicate)
            return left + right

        findings: List[Finding] = []
        reported: Set[Tuple[str, str]] = set()
        for seed in await self._seeds(ctx, base, domain):
            baseline_resp = await probe(seed)
            if not baseline_resp or int(baseline_resp.get("status") or 0) == 0:
                continue
            baseline = _signature(baseline_resp)

            def diff_pred(resp: Optional[Dict],
                          _b: Tuple = baseline) -> bool:
                return resp is not None and _differs(_signature(resp), _b)
            diff_pred.__name__ = "diff_pred"

            def err_pred(resp: Optional[Dict],
                         _b: Tuple = baseline) -> bool:
                return resp is not None and _signature(resp)[3] \
                    and not _b[3]
            err_pred.__name__ = "err_pred"

            changed = await bisect(seed, PARAMS, diff_pred)
            err_params = await bisect(seed, PARAMS, err_pred)
            err_set = set(err_params)
            for pname in err_params:
                key = (seed, pname)
                if key in reported:
                    continue
                reported.add(key)
                findings.append(self._f(
                    "api", "sqli_suspect_param",
                    f"Parameter '{pname}' at {seed} produces a database "
                    f"error signature with a quote marker - SQLi "
                    f"SUSPECT, verify manually",
                    source="arjun-style parameter differential",
                    source_url=seed, confidence=55, passive=False,
                    evidence={"severity": "medium", "parameter": pname,
                              "marker": "single-quote error differential",
                              "confirmed": False,
                              "remediation": ("Use parameterized queries "
                                              "for this parameter and "
                                              "suppress DB error output.")}))
            for pname in changed:
                if pname in err_set:
                    continue
                key = (seed, pname)
                if key in reported:
                    continue
                reported.add(key)
                if ID_LIKE.search(pname):
                    findings.append(self._f(
                        "api", "idor_suspect_param",
                        f"Hidden id-shaped parameter '{pname}' at {seed} "
                        f"changes the response - IDOR SUSPECT, verify "
                        f"with a second account",
                        source="arjun-style parameter differential",
                        source_url=seed, confidence=55, passive=False,
                        evidence={"severity": "medium",
                                  "parameter": pname, "confirmed": False,
                                  "remediation": ("Enforce object-level "
                                                  "authorization on this "
                                                  "parameter; do not "
                                                  "trust client-supplied "
                                                  "ids.")}))
                else:
                    findings.append(self._f(
                        "api", "hidden_param_behavior",
                        f"Hidden parameter '{pname}' at {seed} changes "
                        f"the response",
                        source="arjun-style parameter differential",
                        source_url=seed, confidence=60, passive=False,
                        evidence={"severity": "low", "parameter": pname,
                                  "remediation": ("Review undocumented "
                                                  "parameters; remove "
                                                  "or document and "
                                                  "validate them.")}))
                ctx.publish("params", f"{seed}?{pname}=")
        result = self._ok(findings,
                          f"{len(findings)} behaviour-changing params "
                          f"across seeds")
        result.duration_ms = int((time.time() - start) * 1000)
        return result
