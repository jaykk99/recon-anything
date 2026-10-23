"""Crypto pack: DNS traces of crypto services.

Payment pointers and service wiring published in DNS itself:
OpenAlias records (oa1:), BIP-353 Bitcoin payment instructions
(_bitcoin-payment), and CNAMEs delegating the target's web/payment
surface to hosted crypto services. Small, passive, keyless queries
against public resolvers - no packets to the target's own servers.
"""
from __future__ import annotations

import asyncio
import time
from typing import List

import dns.asyncresolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


async def _txt_records(name: str) -> List[str]:
    out: List[str] = []
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6
    try:
        ans = await resolver.resolve(name, "TXT")
        for r in ans:
            out.append(b"".join(
                p if isinstance(p, bytes) else p.encode()
                for p in r.strings).decode("utf-8", "replace")
                if hasattr(r, "strings") else str(r).strip('"'))
    except Exception:
        pass
    return out


class _DnsPackPlugin(Plugin):
    id = None  # abstract base - see cryptopack_util.PackPlugin
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 30


class CpDnsOpenalias(_DnsPackPlugin):
    id = "cp_dns_openalias"
    label = "DNS: OpenAlias payment records"
    description = ("OpenAlias (oa1:) TXT records: human-readable "
                   "crypto payment addresses bound to the domain, "
                   "per chain (xmr/btc/eth/...).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        for txt in await _txt_records(domain):
            if "oa1:" in txt:
                chain = txt.split("oa1:", 1)[1].split(";", 1)[0].strip()
                findings.append(self._f(
                    "crypto", "openalias_record",
                    f"OpenAlias record for {chain}: {txt[:120]}",
                    source="DNS TXT (OpenAlias)", confidence=90,
                    passive=True, evidence={"record": txt[:300]}))
        res = self._ok(findings, f"{len(findings)} OpenAlias record(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class CpDnsBip353(_DnsPackPlugin):
    id = "cp_dns_bip353"
    label = "DNS: BIP-353 payment instructions"
    description = ("BIP-353 ₿ DNS payment instructions under "
                   "_bitcoin-payment: BOLT12 offers / Lightning "
                   "addresses bound to the domain.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        names = [f"_bitcoin-payment.{domain}", domain]
        for name in names:
            for txt in await _txt_records(name):
                if ("₿" in txt or "bitcoin:" in txt
                        or "lno1" in txt or "lnbc" in txt):
                    findings.append(self._f(
                        "crypto", "bip353_record",
                        f"BIP-353 payment record at {name}: {txt[:120]}",
                        source="DNS TXT (BIP-353)", confidence=90,
                        passive=True, evidence={"record": txt[:300]}))
        res = self._ok(findings, f"{len(findings)} BIP-353 record(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


_CRYPTO_CNAME_SUFFIXES = (
    ".btcpay.cloud", ".btcpay.store", ".coinbase.com",
    ".commerce.coinbase.com", ".opennode.com", ".bitpay.com",
    ".coingate.com", ".nowpayments.io",
)


class CpDnsCryptoCnames(_DnsPackPlugin):
    id = "cp_dns_crypto_cnames"
    label = "DNS: CNAMEs to hosted crypto services"
    description = ("CNAME records delegating the domain (or www/pay/"
                   "checkout subdomains) to hosted crypto payment "
                   "services - the target's payment surface lives on "
                   "someone else's infrastructure.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6

        async def _cname(name: str):
            try:
                ans = await resolver.resolve(name, "CNAME")
                return [str(r.target).rstrip(".").lower() for r in ans]
            except Exception:
                return []

        names = [domain, f"www.{domain}", f"pay.{domain}",
                 f"checkout.{domain}", f"shop.{domain}"]
        results = await asyncio.gather(*[_cname(n) for n in names])
        for name, targets_ in zip(names, results):
            for tgt in targets_:
                if any(tgt.endswith(s) for s in _CRYPTO_CNAME_SUFFIXES):
                    findings.append(self._f(
                        "crypto", "crypto_service_cname",
                        f"{name} CNAME -> {tgt} (hosted crypto service)",
                        source="DNS CNAME", confidence=88, passive=True,
                        evidence={"host": name, "cname": tgt}))
        res = self._ok(findings, f"{len(findings)} crypto CNAME(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
