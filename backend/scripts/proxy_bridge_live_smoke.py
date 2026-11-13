"""Live smoke run for Wave 1.3 (read-only).

    python -m scripts.proxy_bridge_live_smoke [--out out.json]

1. Proxy: USDC on Ethereum (0xA0b8...eB48) - reads the EIP-1967
   implementation / admin / beacon slots + the ZeppelinOS slot live,
   fetches the live implementation's bytecode and verified source
   (Blockscout, then Sourcify - both keyless), and re-runs the
   defense / fork-path analysis on it.
2. Bridge locked-vs-minted: WBTC locked in Arbitrum's L1 ERC20
   gateway (gateway discovered live via L2 gateway
   counterpartGateway()) vs WBTC totalSupply on Arbitrum One.
   WBTC - not USDC: the generic L1 gateway holds only dust USDC
   (35,595 base units, confirmed via Blockscout + two RPCs) while
   USDC.e supply is ~$46.8M, so USDC is escrowed elsewhere and
   would false-fire; WBTC's escrow genuinely sits in this gateway
   (verified live: locked 743,608,272,716 vs supply
   734,816,846,087 satoshis).
3. Bridge quorum (Wormhole): live guardian-set size from the
   Wormhole core contract on Ethereum + the 2/3+1 quorum rule.

eth_getStorageAt / eth_getCode / eth_call only, over the public
keyless RPCs in contract_chain.CHAINS. No transactions, no keys.
Prints a JSON report; findings (if any) are candidates, never
VERIFIED_REAL.
"""
import argparse
import asyncio
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app import proxy_bridge_live as pbl  # noqa: E402

USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDC_E_ARB = "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8"
WBTC_ETH = "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"
WBTC_ARB = "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f"
L1_GATEWAY_ROUTER = "0x72Ce9c846789fdB6fC1f34aC4AD25Dd9ef7031"
L1_ERC20_GATEWAY = "0xa3A7B6F88361F48403514059F1F16C8E78d60EeC"
WORMHOLE_CORE = "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"


def _http_get(url: str, timeout: float = 20):
    req = urllib.request.Request(
        url, headers={"User-Agent": "recon-anything/smoke"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if r.status != 200:
                return None
            return r.read().decode()
    except Exception:
        pass
    # Same shared-egress truncation as the RPC reader: large bodies
    # (verified source) die under urllib while curl fetches them.
    import shutil
    import subprocess

    if not shutil.which("curl"):
        return None
    try:
        proc = subprocess.run(
            ["curl", "-s", "-m", str(int(timeout)), url,
             "-H", "User-Agent: recon-anything/smoke"],
            capture_output=True, timeout=timeout + 5)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    try:
        return proc.stdout.decode()
    except Exception:
        return None


def _unwrap_blockscout_source(raw: str):
    try:
        d = json.loads(raw)
    except Exception:
        return None
    res = d.get("result")
    if isinstance(res, list) and res:
        src = res[0].get("SourceCode") or ""
        if src and src != "Contract source code not verified":
            return src, res[0].get("ContractName", "")
    return None


def _unwrap_sourcify_stdjson(raw: str):
    """Unwrap a Sourcify v2 contract response (live shape, 2026-11-13).

    The v2 API returns the source files in a top-level ``sources``
    dict (path -> {content}) plus ``compilation.name``; the old
    ``?fields=stdJson`` selector 400s ("not a valid field") and the
    ``stdJson`` key does not exist - the input JSON lives under
    ``stdJsonInput`` (no contractName). All three shapes are tried
    so an API drift degrades to "no source", never to a crash.
    """
    try:
        d = json.loads(raw)
    except Exception:
        return None
    sources = {}
    for container in (d.get("stdJson"), d.get("stdJsonInput")):
        if isinstance(container, dict):
            sources = container.get("sources") or {}
            if sources:
                break
    if not sources and isinstance(d.get("sources"), dict):
        sources = d["sources"]
    parts = []
    for _path, entry in sources.items():
        if isinstance(entry, dict) and entry.get("content"):
            parts.append(entry["content"])
    if not parts:
        return None
    name = ""
    comp = d.get("compilation")
    if isinstance(comp, dict):
        name = comp.get("name") or ""
    if not name:
        try:
            target = (d.get("metadata") or {}).get(
                "settings", {}).get("compilationTarget") or {}
            name = next(iter(target.values()), "")
        except Exception:
            name = ""
    return "\n".join(parts), name


def fetch_verified_source_sync(chain_id: int, address: str):
    """Keyless verified-source fetch: Blockscout, then Sourcify v2."""
    if chain_id == 1:
        raw = _http_get(
            "https://eth.blockscout.com/api?module=contract"
            f"&action=getsourcecode&address={address}")
        if raw:
            got = _unwrap_blockscout_source(raw)
            if got:
                return {"source": got[0], "contract_name": got[1],
                        "origin": "blockscout"}
    raw = _http_get(
        "https://sourcify.dev/server/v2/contract/"
        f"{chain_id}/{address}?fields=all")
    if raw:
        got = _unwrap_sourcify_stdjson(raw)
        if got:
            return {"source": got[0], "contract_name": got[1],
                    "origin": "sourcify-v2"}
    return None


async def _proxy_smoke(reader, chain, address, chain_id, label):
    slots = await pbl.read_proxy_slots(reader, chain, address)
    impl = slots.get("implementation")
    out = {"proxy": address, "chain": chain, "slots": slots}
    if not impl:
        out["verdict"] = "degraded"
        out["detail"] = "no implementation slot set"
        return out
    code = await reader.aget_code(chain, impl)
    out["implementation_code_hash"] = pbl.code_hash(code)
    out["implementation_selectors"] = len(
        pbl.extract_selectors(code))
    src = fetch_verified_source_sync(chain_id, impl)
    out["source_origin"] = src["origin"] if src else None
    out["source_contract_name"] = (
        src["contract_name"] if src else None)
    if not src:
        out["verdict"] = "degraded"
        out["detail"] = ("live implementation has no verified source "
                         "via keyless routes - bytecode-only, not "
                         "cleared")
        return out
    hits = pbl.analyze_implementation_source(
        src["source"], contract_name=src["contract_name"])
    out["reanalysis_hits"] = [
        {"id": h.get("kind"), "severity": h.get("severity"),
         "function": h.get("function", ""),
         "report_class": h.get("report_class"),
         "detail": (h.get("detail") or "")[:300]} for h in hits]
    out["verdict"] = "candidate" if hits else "clean"
    return out


async def _bridge_smoke(reader):
    # Discover the L1 gateway for USDC live, never trusting a
    # searched address: the L2 ERC20 gateway's counterpartGateway()
    # IS the L1 gateway; the L1 router's getGateway(USDC) is the
    # second route. Only if both live reads fail, fall back to the
    # documented generic L1 ERC20 gateway.
    gateway = None
    via = ""
    data = "0x" + pbl.selector("counterpartGateway()")
    raw = await reader.aeth_call(
        "arbitrum", "0x09e9222E96E7B4AE2a407B98d48e330053351EEe", data)
    gateway = pbl.decode_address(raw, 0)
    via = "L2 gateway counterpartGateway()"
    if not gateway:
        data = "0x" + pbl.selector("getGateway(address)") + \
            pbl.pad_addr(USDC_ETH)
        raw = await reader.aeth_call(
            "ethereum", L1_GATEWAY_ROUTER, data)
        gateway = pbl.decode_address(raw, 0)
        via = "L1 router getGateway(USDC)"
    if not gateway:
        gateway = L1_ERC20_GATEWAY
        via = "fallback: documented L1 ERC20 gateway"
    cfg = pbl.BridgeLockMintConfig(
        "ethereum", gateway, WBTC_ETH, "arbitrum", WBTC_ARB,
        label="arbitrum-wbtc")
    res = await pbl.check_locked_vs_minted(reader, cfg)
    res["gateway_discovery"] = via
    res["gateway"] = gateway
    return res


async def _wormhole_quorum_smoke(reader):
    data = "0x" + pbl.selector("getCurrentGuardianSetIndex()")
    raw = await reader.aeth_call("ethereum", WORMHOLE_CORE, data)
    idx = pbl.decode_uint(raw, 0)
    out = {"bridge": "wormhole-core", "chain": "ethereum",
           "contract": WORMHOLE_CORE, "guardian_set_index": idx}
    if idx is None:
        out["verdict"] = "degraded"
        out["detail"] = "guardian set index unreadable"
        return out
    data = "0x" + pbl.selector("getGuardianSet(uint32)") + \
        pbl.pad_uint(idx)
    raw = await reader.aeth_call("ethereum", WORMHOLE_CORE, data)
    # GuardianSet struct layout: offset-to-struct, offset-to-keys,
    # expiry, keys-length (see pbl.parse_guardian_set - the length
    # is word 3, NOT word 2).
    parsed = pbl.parse_guardian_set(raw)
    n = parsed["guardian_count"] if parsed else None
    out["guardian_set_expiry"] = (
        parsed["expiry"] if parsed else None)
    out["live_guardians"] = n
    if n is None:
        out["verdict"] = "degraded"
        out["detail"] = "guardian set unreadable"
        return out
    quorum = (2 * n) // 3 + 1  # Wormhole VAA rule: 2/3 + 1
    out["quorum_2_3_plus_1"] = quorum
    out["broken"] = quorum > n or n == 0
    out["verdict"] = "candidate" if out["broken"] else "clean"
    out["detail"] = (f"Wormhole live guardians={n}, quorum "
                     f"(2/3+1)={quorum} - "
                     + ("BROKEN" if out["broken"]
                        else "quorum reachable"))
    return out


async def main_async():
    reader = pbl.SyncRpcReader()
    return {
        "proxy_usdc": await _proxy_smoke(
            reader, "ethereum", USDC_ETH, 1, "usdc"),
        "proxy_usdc_e_arbitrum": await _proxy_smoke(
            reader, "arbitrum", USDC_E_ARB, 42161, "usdc.e"),
        "bridge_arbitrum_wbtc": await _bridge_smoke(reader),
        "bridge_wormhole_quorum": await _wormhole_quorum_smoke(reader),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Wave 1.3 live smoke run (read-only).")
    p.add_argument("--out", help="write report JSON here")
    args = p.parse_args(argv)
    report = asyncio.run(main_async())
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
