"""FFUF-style virtual-host fuzzing (Tier-3 remainder, native).

Master already covers FFUF's content-discovery mode twice over:
gobuster (wordlist content discovery with extension permutations and
404-baseline filtering) and feroxbuster (recursive content discovery),
and parameter fuzzing via param_fuzzer / param_discovery. The FFUF
mode nothing on master does is VHOST fuzzing: wordlist hostnames sent
in the Host header against the target, with ffuf-style match/filter
logic (baseline fingerprint of a random nonexistent vhost; a word is
a hit only when its status/size fingerprint differs from baseline).

GET only, benign words only, rate-limited via the shared limiter.
Authorized testing only.
"""
from __future__ import annotations

import hashlib
import random
import string
import time
from typing import Dict, List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch_many
from .base import Cost, Ctx, Plugin, PluginResult, Target

# Common virtual-host names (dev/staging/internal surfaces + services).
VHOST_WORDS = """www dev staging stage test testing qa uat beta alpha
demo sandbox internal intranet private admin administrator portal
api api-dev api-test gateway gw mail webmail smtp imap pop3 ftp sftp
vpn remote access secure login auth sso idp accounts my account
app apps mobile m blog shop store cdn static assets media files
docs help support wiki git gitlab jenkins ci build deploy monitor
grafana kibana prometheus status health metrics logs db database
mysql pgsql redis elastic search solr mq queue worker jobs cron
node1 node2 web1 web2 srv1 server1 origin direct old new backup
bkp dr failover eu us asia dev1 dev2 test1 stage1 prod production
""".split()

HIT_STATUSES = (200, 201, 204, 301, 302, 307, 308, 401, 403, 405)


def _fingerprint(status: int, text: str) -> Dict:
    body = (text or "")[:4000]
    return {"status": status, "length": len(text or ""),
            "hash": hashlib.sha256(body.encode("utf-8", "replace"))
            .hexdigest()[:16]}


def is_vhost_hit(fp: Dict, baseline: Dict) -> bool:
    """ffuf-style filter: real status + fingerprint != baseline."""
    if not fp or fp.get("status", 0) not in HIT_STATUSES:
        return False
    if baseline and fp.get("status") == baseline.get("status") \
            and fp.get("hash") == baseline.get("hash"):
        return False
    return True


class FfufFuzzPlugin(Plugin):
    id = "ffuf_fuzz"
    label = "FFUF VHost Fuzzing"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 90
    aggressive = True
    description = ("FFUF vhost mode: Host-header wordlist fuzzing with "
                   "baseline status/size filtering. Content discovery "
                   "is covered by gobuster/feroxbuster.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends Host-header "
                                 "fuzz requests)")
        base = await web_base(ctx, target, domain)
        host_for_url = urlparse(base).netloc or domain

        async def probe(host_header: str):
            reqs = [("GET", base, {"headers": {"Host": host_header},
                                   "timeout": 8, "max_retries": 0,
                                   "follow_redirects": False})]
            res = await fetch_many(ctx.http, ctx.limiter, reqs,
                                   concurrency=1, deadline=12)
            r = res[0] if res else None
            if r is None:
                return {"status": 0, "length": 0, "hash": ""}
            return _fingerprint(r.status_code, r.text or "")

        rand = "".join(random.choices(string.ascii_lowercase, k=14))
        baseline = await probe(f"{rand}.{domain}")

        reqs = [("GET", base, {"headers": {"Host": f"{w}.{domain}"},
                               "timeout": 8, "max_retries": 0,
                               "follow_redirects": False})
                for w in VHOST_WORDS]
        results = await fetch_many(ctx.http, ctx.limiter, reqs,
                                   concurrency=6, deadline=60)
        findings = []
        hits = 0
        for word, r in zip(VHOST_WORDS, results):
            if r is None:
                continue
            fp = _fingerprint(r.status_code, r.text or "")
            if not is_vhost_hit(fp, baseline):
                continue
            vhost = f"{word}.{domain}"
            hits += 1
            ctx.publish("subdomains", vhost)
            findings.append(self._f(
                "web", "virtual_host", vhost,
                source="ffuf vhost fuzz", source_url=base,
                confidence=70, passive=False,
                evidence={"severity": "low", "status": fp["status"],
                          "length": fp["length"],
                          "baseline_status": baseline.get("status"),
                          "remediation": "Inventory virtual hosts: "
                                         "remove stale dev/staging "
                                         "vhosts or put them behind "
                                         "auth/VPN."}))
            self._checkpoint(findings)
        res = self._ok(findings,
                       f"{len(VHOST_WORDS)} vhosts fuzzed against "
                       f"{host_for_url}, {hits} differ from baseline")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
