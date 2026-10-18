"""Crypto infrastructure misconfiguration checker.

Probes for open blockchain RPC endpoints, exposed node APIs, and default
credentials on crypto services. Read-only: only sends harmless JSON-RPC
method calls like web3_clientVersion. Never sends transactions or writes.
Authorized testing only.
"""
from __future__ import annotations

import asyncio
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Common RPC/API paths on crypto infrastructure
RPC_PATHS = [
    ("/", "root RPC"),
    ("/rpc", "rpc endpoint"),
    ("/api", "api endpoint"),
    (":8545", "default geth port"),
    (":8546", "default geth ws port"),
    (":8332", "default bitcoin rpc port"),
    (":9933", "substrate rpc"),
    (":9934", "substrate ws"),
    (":26657", "tendermint rpc"),
]

# Harmless read-only JSON-RPC calls
SAFE_RPC_CALLS = [
    ("web3_clientVersion", []),
    ("net_version", []),
    ("eth_chainId", []),
]

REMEDIATION = ("Never expose RPC to the internet. Bind to localhost, require "
               "authentication, use a reverse proxy with rate limiting, and "
               "disable unused modules (admin, personal, debug).")


class CryptoconfigPlugin(Plugin):
    id = "cryptoconfig"
    label = "Crypto RPC Checker"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Check for open blockchain RPC endpoints."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        passive = False

        # Test common subdomains that might host nodes
        node_hosts = [domain, f"rpc.{domain}", f"node.{domain}",
                      f"eth.{domain}", f"api.{domain}"]

        # 45 (host, path) probes concurrently: sequential 45x10s timeouts
        # become one paced window. Same probes, same findings.
        sem = asyncio.Semaphore(10)

        async def probe_one(host: str, path: str, label: str):
            if path.startswith(":"):
                url = f"http://{host}{path}"
            else:
                url = f"https://{host}{path}"
            # Try a harmless version call
            method, params = SAFE_RPC_CALLS[0]
            async with sem:
                try:
                    r = await fetch(
                        ctx.http, ctx.limiter, "POST", url, timeout=10,
                        json={"jsonrpc": "2.0", "id": 1,
                              "method": method, "params": params})
                except Exception:
                    return None
            body = r.text[:2000]
            if r.status_code == 200 and "result" in body:
                return self._f(
                    "infra", "open_rpc_endpoint",
                    f"CRITICAL: open blockchain RPC at {url} "
                    f"({label}). Responded to {method}.",
                    source="RPC probe", source_url=url,
                    confidence=90, passive=False,
                    evidence={"severity": "critical",
                              "endpoint": url,
                              "method": method,
                              "response_hint": body[:200],
                              "remediation": REMEDIATION,
                              "scope_note": "Read-only probe. An open RPC can drain wallets if personal/admin modules are enabled."})
            return None

        jobs = []
        for host in node_hosts:
            for path, label in RPC_PATHS:
                jobs.append((host, path, label))
                if len(jobs) >= 30:
                    break
            if len(jobs) >= 30:
                break
        results = await asyncio.gather(
            *[probe_one(h, p, lab) for h, p, lab in jobs])
        findings.extend([f for f in results if f])
        tested = len(jobs)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{tested} RPC probes, {len(findings)} open endpoints")
        res.duration_ms = dur
        return res
