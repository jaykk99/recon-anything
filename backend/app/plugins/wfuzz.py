"""Wfuzz-style generic web fuzzer (Tier-3, native).

Fuzzes a FUZZ marker in three positions - path segment, query value,
and a request header - with a benign wordlist. Detection is purely
differential: a random-word baseline is fingerprinted per position,
and a payload only counts when its status/size fingerprint differs
from baseline, or when the unique benign marker payload is reflected
unencoded in the response. The marker is a random alphanumeric token:
no attack payloads are ever sent.

GET only, rate-limited. If the target URL itself contains FUZZ,
that exact position is fuzzed instead of the defaults.
"""
from __future__ import annotations

import hashlib
import random
import string
import time
from typing import Dict, List, Tuple
from urllib.parse import quote, urlparse, urlunparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch, fetch_many
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   bounded)

PAYLOADS = """admin test dev staging config backup old api v1 v2 login
search debug internal private public static assets uploads files
images docs help support about contact home index main default user
users account profile settings dashboard portal app web site en fr
""".split()

HIT_STATUSES = (200, 201, 204, 301, 302, 307, 308, 401, 403, 405)


def _fp(status: int, text: str) -> Dict:
    body = (text or "")[:4000]
    return {"status": status, "length": len(text or ""),
            "hash": hashlib.sha256(body.encode("utf-8", "replace"))
            .hexdigest()[:16]}


def is_fuzz_hit(fp: Dict, baseline: Dict) -> bool:
    if not fp or fp.get("status", 0) not in HIT_STATUSES:
        return False
    if baseline and fp.get("status") == baseline.get("status") \
            and fp.get("hash") == baseline.get("hash"):
        return False
    return True


class WfuzzPlugin(Plugin):
    id = "wfuzz"
    label = "Wfuzz Generic Web Fuzzer"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 120
    aggressive = True
    description = ("Generic FUZZ-marker fuzzer for path, query and "
                   "header positions with differential (status/size/"
                   "reflection) detection. Benign payloads only.")

    async def _one(self, ctx: Ctx, url: str, headers=None) -> Dict:
        try:
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", url, timeout=8,
                max_retries=0, follow_redirects=False,
                headers=headers or {}), 10)
            if r is None:
                return {"status": 0, "length": 0, "hash": ""}
            return _fp(r.status_code, r.text or "")
        except Exception:
            return {"status": 0, "length": 0, "hash": ""}

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends fuzz requests)")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        marker = "wfz" + "".join(
            random.choices(string.ascii_lowercase, k=10))
        rand = "".join(random.choices(string.ascii_lowercase, k=12))
        findings: List[Finding] = []
        jobs: List[Tuple[str, str, str]] = []  # (position, payload, url)

        explicit_fuzz = "FUZZ" in (target.normalized or "")
        if explicit_fuzz:
            positions = [("url", target.normalized)]
        else:
            positions = [("path", f"{base}/FUZZ"),
                         ("query", f"{base}/?q=FUZZ")]

        for position, template in positions:
            baseline = await self._one(ctx, template.replace("FUZZ", rand))
            words = list(PAYLOADS) + [marker]
            reqs = [("GET", template.replace("FUZZ", quote(w, safe="")),
                     {"timeout": 8, "max_retries": 0,
                      "follow_redirects": False}) for w in words]
            results = await fetch_many(ctx.http, ctx.limiter, reqs,
                                       concurrency=6, deadline=45)
            for word, r in zip(words, results):
                if r is None:
                    continue
                url = template.replace("FUZZ", quote(word, safe=""))
                body = r.text or ""
                if word == marker:
                    if marker in body and f"&lt;{marker}" not in body:
                        findings.append(self._f(
                            "web", "fuzz_reflection",
                            f"Benign marker reflected unencoded at "
                            f"{urlparse(url).path or '/'} ({position} "
                            f"position) - reflection candidate",
                            source="wfuzz", source_url=url,
                            confidence=65, passive=False,
                            evidence={"severity": "medium",
                                      "position": position,
                                      "remediation": "Encode all reflected "
                                                     "input for its "
                                                     "output context."}))
                    continue
                fp = _fp(r.status_code, body)
                if is_fuzz_hit(fp, baseline):
                    jobs.append((position, word, url))
                    findings.append(self._f(
                        "web", "fuzz_hit",
                        f"{url} -> {fp['status']} ({fp['length']} bytes) "
                        f"differs from {position} baseline",
                        source="wfuzz", source_url=url,
                        confidence=60, passive=False,
                        evidence={"severity": "low",
                                  "position": position, "payload": word,
                                  "status": fp["status"],
                                  "length": fp["length"],
                                  "baseline_status": baseline.get("status"),
                                  "remediation": "Review this fuzz-"
                                                 "discovered response: "
                                                 "confirm the path is "
                                                 "intended and protected."}))
            self._checkpoint(findings)

        # Header position: fuzz X-Forwarded-For style header value is
        # meaningless differentially on most stacks, so fuzz a custom
        # header NAME marker instead: baseline vs marker header present.
        if not explicit_fuzz:
            base_fp = await self._one(ctx, base)
            mark_fp_resp = None
            try:
                mark_fp_resp = await bounded(fetch(
                    ctx.http, ctx.limiter, "GET", base, timeout=8,
                    max_retries=0, follow_redirects=False,
                    headers={"X-Fuzz-Probe": marker}), 10)
            except Exception:
                mark_fp_resp = None
            if mark_fp_resp is not None:
                body = mark_fp_resp.text or ""
                if marker in body:
                    findings.append(self._f(
                        "web", "fuzz_reflection",
                        "Benign header value reflected unencoded in "
                        "response body (header position)",
                        source="wfuzz", source_url=base,
                        confidence=65, passive=False,
                        evidence={"severity": "medium",
                                  "position": "header",
                                  "remediation": "Encode all reflected "
                                                 "input for its output "
                                                 "context."}))
                else:
                    fp = _fp(mark_fp_resp.status_code, body)
                    if is_fuzz_hit(fp, base_fp):
                        findings.append(self._f(
                            "web", "fuzz_hit",
                            f"Header-position probe changes response at "
                            f"{urlparse(base).path or '/'} -> "
                            f"{fp['status']} ({fp['length']} bytes)",
                            source="wfuzz", source_url=base,
                            confidence=55, passive=False,
                            evidence={"severity": "low",
                                      "position": "header",
                                      "remediation": "Review why a "
                                                     "custom header "
                                                     "changes the "
                                                     "response."}))

        res = self._ok(findings,
                       f"fuzzed {len(positions)} positions x "
                       f"{len(PAYLOADS) + 1} payloads, "
                       f"{len(findings)} differential hits")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
