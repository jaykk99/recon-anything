"""Chain coverage matrix for ReconAnything.

Runs the requested chain list through the actual recon stack, one row per
chain, and records three independent facts:

1. DETECT - the chain's real address-detector plugin (the cp_* class the
   registry ships) runs end-to-end against a page containing a valid,
   checksum-correct address for that chain. This exercises the full plugin
   path (collect_texts -> PATTERNS -> checksum validator), not a reimpl.
2. ROUTE  - what the single search bar's classifier does with that address
   (does it become a first-class crypto target, or fall through to
   username/domain?).
3. LIVE   - one read-only probe of the keyless public source the project
   uses for that chain (EVM JSON-RPC eth_chainId/eth_getCode, Blockchair,
   Tronscan, XRPScan, Solana RPC). No key, no transaction, no eth_call.

Chains the project has no live lane for are reported as such instead of
being probed with something the product does not actually use.

Usage:
    python test_chain_matrix.py             # offline + live
    python test_chain_matrix.py --offline   # skip live probes
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "backend"))

import httpx  # noqa: E402

from app.cache import Cache  # noqa: E402
from app.classifier import classify  # noqa: E402
from app.chaindata import (  # noqa: E402
    APTOS_ACCOUNTS, BLOCKCHAIR, DASH_INSIGHT, DOGECHAIN, KOIOS, SOLANA_RPC,
    SUI_COIN_TYPE, SUI_GRAPHQL, TONCENTER, TRONGRID, TRONSCAN, XRPSCAN,
    parse_aptos, parse_blockchair, parse_dash_insight, parse_dogechain,
    parse_esplora, parse_koios, parse_solana_balance, parse_sui, parse_ton,
    parse_tron, parse_trongrid, parse_xrp)
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import cryptopack_util as U  # noqa: E402
from app.plugins.base import Ctx, PageData, Target  # noqa: E402
from app.plugins.registry import discover, for_target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

REG = discover()
DOMAIN = "fixture.test"
H20 = bytes(range(20))


def b58c(payload: bytes) -> str:
    return U.b58check_encode(payload)


def ton_addr() -> str:
    pay = bytes([0x11, 0x00]) + bytes(range(32))
    return base64.urlsafe_b64encode(
        pay + U.crc16_xmodem(pay).to_bytes(2, "big")).decode().rstrip("=")


def dot_addr() -> str:
    pub = bytes([0]) + bytes(range(32))
    ck = hashlib.blake2b(b"SS58PRE" + pub, digest_size=64).digest()[:2]
    return U.b58encode(pub + ck)


# ---------------------------------------------------------------------------
# Chain rows.
#
# sample       : text handed to the detector plugin (valid address + context
#                where the format is context-anchored)
# detector/key : the plugin and finding key that must fire
# live         : ("evm", chain_id_in_config, contract_probe) | ("rpc", url,
#                expected_chain_id) | ("blockchair", slug) | ("tron"|"xrp"|
#                "solana", address) | ("none", reason)
# ---------------------------------------------------------------------------
ROWS = [
    # --- UTXO ---
    dict(chain="Bitcoin", group="UTXO",
         sample="Donate BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
         detector="cp_btc_legacy", key="btc_address_legacy",
         live=("esplora", "https://mempool.space/api",
               "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")),
    dict(chain="Litecoin", group="UTXO",
         sample=f"LTC: {b58c(bytes([0x30]) + H20)}",
         detector="cp_ltc_validated", key="ltc_address",
         live=("esplora", "https://litecoinspace.org/api",
               b58c(bytes([0x30]) + H20))),
    dict(chain="Dogecoin", group="UTXO",
         sample=f"DOGE: {b58c(bytes([0x1E]) + H20)}",
         detector="cp_doge_validated", key="doge_address",
         live=("dogechain", b58c(bytes([0x1E]) + H20))),
    dict(chain="Bitcoin Cash", group="UTXO",
         sample="bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
         detector="cp_bch_addr", key="bch_address",
         live=("blockchair", "bitcoin-cash",
               "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")),
    dict(chain="Dash", group="UTXO",
         sample=f"DASH: {b58c(bytes([0x4C]) + H20)}",
         detector="cp_dash_addr", key="dash_address",
         live=("dash", b58c(bytes([0x4C]) + H20))),

    # --- account / smart contract ---
    dict(chain="Ethereum", group="Account",
         sample="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
         detector="cp_eth_eip55", key="eth_address_checksummed",
         live=("evm", "ethereum", "0xdAC17F958D2ee523a2206206994597C13D831ec7")),
    dict(chain="Solana", group="Account",
         sample="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
         detector="cp_solana_addr", key="solana_address",
         live=("solana", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")),
    dict(chain="BNB Chain", group="Account",
         sample="0x55d398326f99059fF775485246999027B3197955",
         detector="cp_eth_eip55", key="eth_address_checksummed",
         live=("evm", "bsc", "0x55d398326f99059fF775485246999027B3197955")),
    dict(chain="TRON", group="Account",
         sample="TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7",
         detector="cp_trx_validated", key="trx_address",
         live=("tron", "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7")),
    dict(chain="Cardano", group="Account",
         sample=U.bech32_encode("addr", bytes(range(57))),
         detector="cp_ada_addr", key="ada_address",
         # Cardano docs' funded example address (1 ADA), so the probe
         # proves the parser on a real account rather than an empty row.
         live=("cardano", "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x")),
    dict(chain="Polygon", group="Account",
         sample="0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
         detector="cp_eth_eip55", key="eth_address_checksummed",
         live=("evm", "polygon", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359")),
    dict(chain="Avalanche", group="Account",
         # C-Chain is the EVM lane the list means; X-Chain has its own
         # bech32 detector, checked separately below.
         sample="0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
         detector="cp_eth_eip55", key="eth_address_checksummed",
         live=("evm", "avalanche",
               "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E")),
    dict(chain="Arbitrum", group="Account",
         sample="0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
         detector="cp_eth_eip55", key="eth_address_checksummed",
         live=("evm", "arbitrum",
               "0xaf88d065e77c8cC2239327C5EDb3A432268e5831")),
    dict(chain="Optimism", group="Account",
         sample="0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
         detector="cp_eth_eip55", key="eth_address_checksummed",
         live=("evm", "optimism",
               "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85")),
    dict(chain="Base", group="Account",
         sample="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
         detector="cp_eth_eip55", key="eth_address_checksummed",
         live=("evm", "base", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")),
    dict(chain="XRP Ledger", group="Account",
         sample="rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
         detector="cp_xrp_addr", key="xrp_address",
         live=("xrp", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")),
    dict(chain="Toncoin", group="Account",
         sample=f"TON wallet: {ton_addr()}",
         detector="cp_ton_addr", key="ton_address",
         live=("ton", ton_addr())),
    dict(chain="Polkadot", group="Account",
         sample=dot_addr(),
         detector="cp_dot_addr", key="dot_address",
         live=("none", "no keyless lane: Subscan is API-key gated")),
    dict(chain="Sui", group="Account",
         sample="sui:0x" + "ab" * 32,
         detector="cp_sui_addr", key="sui_address",
         live=("sui", "0x0000000000000000000000000000000000000000000000000000000000000002")),
    dict(chain="Aptos", group="Account",
         sample="aptos:0x" + "cd" * 32,
         detector="cp_aptos_addr", key="aptos_address",
         live=("aptos", "0x1")),

    # --- privacy ---
    dict(chain="Monero", group="Privacy",
         sample=U.xmr_encode(bytes([0x12]) + bytes(range(32))
                             + bytes(range(32, 64))),
         detector="cp_xmr_standard", key="xmr_address",
         live=("none", "privacy chain: detection only by design")),
    dict(chain="Zcash", group="Privacy",
         sample=f"ZEC: {b58c(b'\x1c\xb8' + H20)}",
         detector="cp_zec_addr", key="zec_address",
         live=("blockchair", "zcash", b58c(b"\x1c\xb8" + H20))),

    # --- stablecoins ---
    dict(chain="USDT", group="Stablecoin",
         sample="0xdAC17F958D2ee523a2206206994597C13D831ec7",
         detector="cp_web3_canonical_contracts", key="contract_usdt",
         live=("evm", "ethereum", "0xdAC17F958D2ee523a2206206994597C13D831ec7")),
    dict(chain="USDC", group="Stablecoin",
         sample="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
         detector="cp_web3_canonical_contracts", key="contract_usdc",
         live=("evm", "ethereum", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")),
    dict(chain="DAI", group="Stablecoin",
         sample="0x6B175474E89094C44Da98b954EedeAC495271d0F",
         detector="cp_web3_canonical_contracts", key="contract_dai",
         live=("evm", "ethereum", "0x6B175474E89094C44Da98b954EedeAC495271d0F")),
]

# Extra lanes the requested list implies but that are not the row's main
# address shape.
EXTRAS = [
    dict(chain="Avalanche X-Chain", detector="cp_avax_addr",
         sample="avax1" + "q" * 38),
]


# ---------------------------------------------------------------------------
# Offline: detector end-to-end + fleet collision scan + classifier
# ---------------------------------------------------------------------------

def make_ctx(html: str) -> Ctx:
    ctx = Ctx(run_id="chain-matrix", mode="passive", http=None,
              cache=Cache(), keys={})

    async def fetch_page(url, timeout=10):
        return PageData({"status_code": 200, "headers": {},
                         "text": html, "url": f"https://{DOMAIN}/"})
    ctx.fetch_page = fetch_page
    return ctx


async def run_detector(pid: str, sample: str) -> list:
    """Run the real plugin class over a stubbed page; return finding keys."""
    cls = REG[pid]
    plugin = cls()
    target = Target(raw=DOMAIN, type="domain", normalized=DOMAIN)
    result = await plugin.run(target, make_ctx(f"<html><body>{sample}"
                                               "</body></html>"))
    return [f.key for f in result.findings]


def scan_fleet(text: str) -> list:
    """Every registered cp_* detector against the same text (collisions)."""
    hits = []
    for pid, cls in REG.items():
        if not pid.startswith("cp_"):
            continue
        plugin = cls()
        patterns = getattr(plugin, "PATTERNS", None)
        if not patterns:
            continue
        ctx_re = (re.compile(plugin.CONTEXT_RE, re.I)
                  if plugin.CONTEXT_RE else None)
        for rx, key, _label, _conf, validator in plugin._patterns():
            for m in rx.finditer(text):
                value = m.group(plugin.VALUE_GROUP)
                if validator is not None:
                    try:
                        if not validator(value):
                            continue
                    except Exception:
                        continue
                if ctx_re is not None:
                    lo = max(0, m.start() - plugin.WINDOW)
                    hi = min(len(text), m.end() + plugin.WINDOW)
                    if not ctx_re.search(text[lo:hi]):
                        continue
                hits.append((pid, key))
    return sorted(set(hits))


# ---------------------------------------------------------------------------
# Live: one read-only call per chain, through the project's own code paths
# ---------------------------------------------------------------------------

async def live_probe(client: httpx.AsyncClient, spec: tuple, ctx) -> dict:
    kind = spec[0]
    t0 = time.monotonic()

    def done(ok, detail):
        return {"ok": ok, "detail": detail,
                "ms": int((time.monotonic() - t0) * 1000)}

    if kind == "none":
        return done(None, spec[1])

    try:
        if kind == "evm":
            chain_id, addr = spec[1], spec[2]
            chain = cc.CHAINS.get(chain_id)
            if chain is None:
                return done(False, f"chain '{chain_id}' missing from "
                                   "contract_chain.CHAINS")
            head = await cc._rpc_post(
                ctx, chain.rpc_urls[0],
                {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId",
                 "params": []})
            got_id = int(head["result"], 16) if head else None
            code = await cc.rpc_get_code(ctx, chain, addr)
            has_code = bool(code and code != "0x")
            # The contract-recon lane itself: verified source (keyless
            # Blockscout -> Sourcify) then the static analyzer.
            meta = await cc.fetch_verified_source(ctx, chain, addr)
            src = (meta or {}).get("source") if isinstance(meta, dict) else None
            issues = (cc.analyze_contract_source(src, meta or {})
                      if src else [])
            ok = got_id == chain.chain_id and has_code
            code_txt = "yes" if has_code else repr(code)
            src_txt = (f"{len(src) / 1024:.1f}KB/{len(issues)} issues"
                       if src else "none")
            return done(ok, f"id={got_id}/{chain.chain_id} code={code_txt} "
                            f"source={src_txt}")
        if kind == "rpc":
            url, want = spec[1], spec[2]
            r = await client.post(url, json={
                "jsonrpc": "2.0", "id": 1, "method": "eth_chainId",
                "params": []}, timeout=12)
            d = r.json() if r.status_code == 200 else {}
            got = int(d["result"], 16) if d.get("result") else None
            return done(got == want,
                        f"public RPC chainId={got} (want {want})")
        if kind == "blockchair":
            slug, addr = spec[1], spec[2]
            r = await client.get(BLOCKCHAIR.format(slug=slug, addr=addr),
                                 timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_blockchair(r.json(), addr)
            return done(bool(prof),
                        f"balance={prof.get('balance')} "
                        f"tx={prof.get('tx_count')}")
        if kind == "esplora":
            base, addr = spec[1], spec[2]
            r = await client.get(f"{base.rstrip('/')}/address/{addr}",
                                 timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_esplora(r.json(), addr)
            return done(bool(prof), f"balance={prof.get('balance')} "
                                    f"tx={prof.get('tx_count')}")
        if kind == "dogechain":
            r = await client.get(DOGECHAIN.format(addr=spec[1]), timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_dogechain(r.json())
            return done(bool(prof), f"balance={prof.get('balance')} DOGE")
        if kind == "dash":
            r = await client.get(DASH_INSIGHT.format(addr=spec[1]),
                                 timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_dash_insight(r.json())
            return done(bool(prof), f"balance={prof.get('balance')} DASH")
        if kind == "cardano":
            r = await client.post(KOIOS, json={"_addresses": [spec[1]]},
                                  timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_koios(r.json())
            return done(bool(prof), f"balance={prof.get('balance')} ADA")
        if kind == "ton":
            r = await client.get(TONCENTER.format(addr=spec[1]), timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_ton(r.json())
            return done(bool(prof), f"balance={prof.get('balance')} TON")
        if kind == "sui":
            query = ("query { address(address: \"%s\") { balance("
                     "coinType: \"%s\") { totalBalance } } }"
                     % (spec[1], SUI_COIN_TYPE))
            r = await client.post(SUI_GRAPHQL, json={"query": query},
                                  timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_sui(r.json())
            return done(bool(prof), f"balance={prof.get('balance')} SUI")
        if kind == "aptos":
            r = await client.get(APTOS_ACCOUNTS.format(addr=spec[1]),
                                 timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_aptos(r.json())
            return done(prof is not None,
                        f"balance={prof.get('balance')} APT")
        if kind == "tron":
            r = await client.get(TRONGRID.format(addr=spec[1]), timeout=15)
            if r.status_code == 200:
                prof = parse_trongrid(r.json())
                if prof:
                    return done(True, f"balance={prof.get('balance')} TRX "
                                      "(TronGrid)")
            r = await client.get(TRONSCAN.format(addr=spec[1]), timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_tron(r.json())
            return done(bool(prof), f"balance={prof.get('balance')} TRX")
        if kind == "xrp":
            r = await client.get(XRPSCAN.format(addr=spec[1]), timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_xrp(r.json())
            return done(bool(prof), f"balance={prof.get('balance')} XRP")
        if kind == "solana":
            r = await client.post(SOLANA_RPC, json={
                "jsonrpc": "2.0", "id": 1, "method": "getBalance",
                "params": [spec[1]]}, timeout=15)
            if r.status_code != 200:
                return done(False, f"HTTP {r.status_code}")
            prof = parse_solana_balance(r.json())
            return done(bool(prof), f"lamports decoded={prof.get('balance')}")
    except Exception as exc:  # noqa: BLE001 - a probe failure is a result
        return done(False, f"{type(exc).__name__}: {exc}"[:120])
    return done(False, f"unknown live kind {kind!r}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

async def run(live: bool) -> int:
    rows = []
    classifier_supported = {"Bitcoin", "Ethereum", "Solana"}
    failures = 0

    async with httpx.AsyncClient(follow_redirects=True) as client:
        ctx = Ctx(run_id="chain-matrix-live", mode="passive", http=client,
                  cache=Cache(), keys={}, limiter=RateLimiter(default_rps=8))
        for row in ROWS:
            addr_text = row["sample"]
            keys = await run_detector(row["detector"], addr_text)
            detected = row["key"] in keys

            # collision scan over every detector
            addr_only = max(re.findall(r"[^\s]+", addr_text),
                            key=len) if addr_text.split() else addr_text
            fleet = scan_fleet(addr_text)
            extra = [f"{p}.{k}" for p, k in fleet if p != row["detector"]]

            cls = classify(addr_only)
            routed = cls["type"]
            # How much of the plugin fleet would actually run if this
            # address were pasted as the scan target?
            runnable = for_target(routed)
            chain_detectors = sorted(p.id for p in runnable
                                     if p.id.startswith("cp_"))
            if (routed == "solana_contract"
                    and any(p.id == "solana_contract" for p in runnable)):
                chain_detectors.append("solana_contract")

            live_res = {"ok": None, "detail": "skipped (--offline)", "ms": 0}
            if live:
                live_res = await live_probe(client, row["live"], ctx)

            ok_detect = detected
            if row["chain"] in classifier_supported and routed not in (
                    "crypto_wallet", "solana_contract"):
                ok_detect = False
            # The health contract: an address that IS classified crypto
            # must schedule the detector that understands its chain.
            if (routed == "crypto_wallet"
                    and row["detector"] not in chain_detectors):
                ok_detect = False
            if (routed == "solana_contract"
                    and "solana_contract" not in chain_detectors):
                ok_detect = False
            if not ok_detect:
                failures += 1
            rows.append(dict(chain=row["chain"], group=row["group"],
                             detector=row["detector"], expected=row["key"],
                             detected=detected, extra_detectors=extra,
                             classified_as=routed,
                             classifier_conf=cls.get("confidence"),
                             plugins_runnable=len(runnable),
                             chain_detectors_runnable=chain_detectors,
                             live=live_res))

    # extras: X-Chain bech32 (not part of the main list rows)
    extras = []
    for ex in EXTRAS:
        tq = U.bech32_encode("avax", bytes(range(20)))
        text = f"Avalanche X-Chain: {tq}"
        keys = await run_detector(ex["detector"], text)
        extras.append(dict(chain=ex["chain"], sample=tq,
                           detected=keys != [], keys=keys))

    print(f"{'CHAIN':<18}{'GROUP':<11}{'DETECT':<8}{'CLASSIFIED AS':<20}"
          f"{'PLUGINS':<9}{'LIVE':<8}DETAIL")
    print("-" * 126)
    for r in rows:
        detect = "PASS" if r["detected"] else "FAIL"
        lv = r["live"]
        live_tag = ("n/a" if lv["ok"] is None else
                    ("PASS" if lv["ok"] else "FAIL"))
        print(f"{r['chain']:<18}{r['group']:<11}{detect:<8}"
              f"{r['classified_as']:<20}{r['plugins_runnable']:<9}"
              f"{live_tag:<8}{lv['detail'][:52]}")
        if r["extra_detectors"]:
            print(f"{'':<18}collisions: {', '.join(r['extra_detectors'])[:90]}")
    print("-" * 126)
    for e in extras:
        print(f"{e['chain']:<18}{'Account':<11}"
              f"{'PASS' if e['detected'] else 'FAIL':<8}"
              f"{'bech32 detector':<20}{'n/a':<8}{', '.join(e['keys'])[:56]}")

    detected_n = sum(1 for r in rows if r["detected"])
    live_rows = [r for r in rows if r["live"]["ok"] is not None]
    live_n = sum(1 for r in live_rows if r["live"]["ok"])
    routed_n = sum(1 for r in rows
                   if r["classified_as"] in ("crypto_wallet",
                                             "solana_contract"))
    print(f"\nDETECT {detected_n}/{len(rows)} chains   "
          f"FIRST-CLASS TARGETS {routed_n}/{len(rows)}   "
          f"LIVE {live_n}/{len(live_rows)} probes")
    blind = [r["chain"] for r in rows
             if r["detected"] and not r["chain_detectors_runnable"]]
    print("Detectors that ROUTE when the address is the scan target (i.e. "
          "its detector would actually be scheduled): "
          f"{len(rows) - len(blind)}/{len(rows)}")
    print(f"Detected but unrouted as a target: {', '.join(blind)}")
    gaps = [r["chain"] for r in rows if r["classified_as"] not in
            ("crypto_wallet", "solana_contract")]
    print("Not first-class targets (fall through the search bar): "
          f"{', '.join(gaps)}")
    no_live = [r["chain"] for r in rows if r["live"]["ok"] is None]
    print(f"No live lane: {', '.join(no_live)}")

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "runs", "chain_matrix.json")
    try:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"rows": rows, "extras": extras}, fh, indent=2)
        print(f"JSON: {out}")
    except OSError as exc:
        print(f"JSON write skipped: {exc}")

    print("\nRESULT:", "PASS" if failures == 0 else f"FAIL ({failures})")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run(live="--offline" not in sys.argv)))
