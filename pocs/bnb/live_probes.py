"""Live read-only probes of BNB Smart Chain mainnet (and Chapel testnet).

READ-ONLY. Every call is eth_call / eth_getBlockByNumber / eth_getCode
against public JSON-RPC endpoints. Nothing is broadcast, no key is
used, no account is touched. Used to check the live state behind the
Parlia flaws in the 2026-11-17 BNB Chain analysis (P-02/P-04/P-05/
P-07/P-08 system-contract state, P-10 header timing).

Selectors were derived with the repo's own keccak helper
(app.plugins.contract_sim.function_selector) and verified against
the official ABIs in bnb-chain/bsc-genesis-contract (abi/
bscvalidatorset.abi, slashindicator.abi).

Usage:
    python3 pocs/bnb/live_probes.py [--testnet] [--out FILE]
    python3 pocs/bnb/live_probes.py --plugin   # also run the real
        # bnb_system_state plugin end-to-end with a live httpx ctx
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

# Transport: httpx through the explicit egress proxy. urllib through
# the same proxy intermittently stalls (timeouts on every endpoint,
# 2026-11-18) while httpx + this proxy stays clean - the same path
# the bnb_system_state plugin run uses. No credentials in the URL:
# the proxy accepts unauthenticated CONNECT from this VM.
_HTTP = httpx.Client(timeout=20, trust_env=False,
                     proxy="http://hatch-egress-proxy:3128")

MAINNET_RPCS = [
    # publicnode first: the binance dataseeds intermittently time
    # out through the egress proxy (2026-11-17/18), ankr rate-limits
    # to an auth error under load. Order is preference, not trust.
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed.binance.org",
    "https://bsc-dataseed1.binance.org",
    "https://rpc.ankr.com/bsc",
]
TESTNET_RPCS = [
    "https://data-seed-prebsc-1-s1.binance.org:8545",
    "https://data-seed-prebsc-2-s1.binance.org:8545",
    "https://bsc-testnet-rpc.publicnode.com",
]

VALIDATOR_SET = "0x0000000000000000000000000000000000001000"
SLASH_INDICATOR = "0x0000000000000000000000000000000000001001"
STAKE_HUB = "0x0000000000000000000000000000000000002002"
FROM = "0x00000000000000000000000000000000deaDBeef"

# name -> (to, selector, arg_words)
CALLS = [
    ("validators", VALIDATOR_SET, "b7ab4db5", []),
    ("numOfCabinets", VALIDATOR_SET, "7a84ca2a", []),
    ("maxNumOfWorkingCandidates", VALIDATOR_SET, "f92eb86b", []),
    ("miningValidators", VALIDATOR_SET, "4df6e0c3", []),
    ("turnLength", VALIDATOR_SET, "8c5d749d", []),
    ("misdemeanorThreshold", SLASH_INDICATOR, "567a372d", []),
    ("felonyThreshold", SLASH_INDICATOR, "389f4f71", []),
    ("felonySlashScope", SLASH_INDICATOR, "9f804f5f", []),
    ("enableMaliciousVoteSlash", SLASH_INDICATOR, "22d1e80b", []),
    ("downtimeSlashAmount", STAKE_HUB, "d8ca511f", []),
    ("felonySlashAmount", STAKE_HUB, "bdceadf3", []),
    ("downtimeJailTime", STAKE_HUB, "76e7d6d6", []),
    ("felonyJailTime", STAKE_HUB, "f1f74d84", []),
]


def rpc(url: str, method: str, params, timeout: int = 20):
    payload = {"jsonrpc": "2.0", "id": 1,
               "method": method, "params": params}
    last_err = None
    for attempt in range(3):
        try:
            r = _HTTP.post(url, json=payload, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:  # noqa: BLE001 - retry, then raise
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    raise last_err


def rpc_any(urls, method, params, timeout: int = 15):
    last_err = None
    for url in urls:
        try:
            d = rpc(url, method, params, timeout)
        except Exception as e:  # noqa: BLE001 - try next endpoint
            last_err = str(e)[:120]
            continue
        if isinstance(d, dict) and "result" in d \
                and d["result"] is not None:
            return d["result"], url
        if isinstance(d, dict) and d.get("error") is not None:
            last_err = str(d["error"])[:120]
            continue
    raise RuntimeError(f"all RPC endpoints failed for {method}: {last_err}")


def eth_call(urls, to: str, data: str):
    return rpc_any(urls, "eth_call",
                   [{"from": FROM, "to": to, "data": data}, "latest"])


def decode_uint(hexstr: str, word: int = 0):
    if not isinstance(hexstr, str) or not hexstr.startswith("0x"):
        return None
    h = hexstr[2:]
    s = word * 64
    if len(h) < s + 64:
        return None
    try:
        return int(h[s:s + 64], 16)
    except ValueError:
        return None


def decode_addrs(hexstr: str):
    if not isinstance(hexstr, str) or not hexstr.startswith("0x"):
        return []
    h = hexstr[2:]
    if len(h) < 128:
        return []
    try:
        off = int(h[0:64], 16)
        n = int(h[off * 2:off * 2 + 64], 16)
    except ValueError:
        return []
    out = []
    base = off * 2 + 64
    for i in range(min(n, 200)):
        chunk = h[base + i * 64: base + (i + 1) * 64]
        if len(chunk) < 64:
            break
        out.append("0x" + chunk[24:64])
    return out


def probe(urls, chain_id: int):
    out: dict = {"chain_id": chain_id, "rpc_used": {}, "calls": {},
                 "headers": [], "codes": {}}
    latest_hex, url = rpc_any(urls, "eth_blockNumber", [])
    latest = int(latest_hex, 16)
    out["latest_block"] = latest
    out["rpc_used"]["eth_blockNumber"] = url
    # Recent headers: inter-block spacing + miner + gas limit (P-10, P-02).
    for n in range(latest, latest - 12, -1):
        blk, url = rpc_any(urls, "eth_getBlockByNumber",
                           [hex(n), False])
        out["headers"].append({
            "number": n,
            "timestamp": int(blk["timestamp"], 16),
            "miner": blk["miner"],
            "gasLimit": int(blk["gasLimit"], 16),
            "gasUsed": int(blk["gasUsed"], 16),
            "txs": len(blk["transactions"]),
        })
    out["headers"].sort(key=lambda b: b["number"])
    deltas = [b2["timestamp"] - b1["timestamp"]
              for b1, b2 in zip(out["headers"], out["headers"][1:])]
    out["header_time_deltas_s"] = deltas
    out["local_time_at_probe"] = int(time.time())
    out["latest_block_ahead_of_local_s"] = (
        out["headers"][-1]["timestamp"] - out["local_time_at_probe"])
    for name, to, sel, _args in CALLS:
        data = "0x" + sel
        res, url = eth_call(urls, to, data)
        out["calls"][name] = res if isinstance(res, dict) else res
        out["rpc_used"][name] = url
    # Slash indicators for the first 3 mining validators (public state).
    mining = decode_addrs(out["calls"].get("miningValidators", ""))
    out["mining_validators"] = mining
    out["validators"] = decode_addrs(out["calls"].get("validators", ""))
    inds = {}
    for a in mining[:3]:
        data = "0x37c8dab9" + "0" * 24 + a[2:]
        res, url = eth_call(urls, SLASH_INDICATOR, data)
        if isinstance(res, str):
            inds[a] = {"height": decode_uint(res, 0),
                       "count": decode_uint(res, 1)}
        else:
            inds[a] = res
    out["slash_indicators_first3_mining"] = inds
    for name, addr in (("ValidatorSet", VALIDATOR_SET),
                       ("SlashIndicator", SLASH_INDICATOR),
                       ("StakeHub", STAKE_HUB)):
        code, url = rpc_any(urls, "eth_getCode", [addr, "latest"])
        out["codes"][name] = {"bytes": (len(code) - 2) // 2
                              if isinstance(code, str) else None,
                              "deployed": bool(isinstance(code, str)
                                               and len(code) > 2)}
    # Decoded scalar view.
    c = out["calls"]
    out["decoded"] = {
        "validators": len(out["validators"]),
        "mining_validators": len(mining),
        "numOfCabinets": decode_uint(c.get("numOfCabinets", ""), 0),
        "maxNumOfWorkingCandidates": decode_uint(
            c.get("maxNumOfWorkingCandidates", ""), 0),
        "turnLength": decode_uint(c.get("turnLength", ""), 0),
        "misdemeanorThreshold": decode_uint(
            c.get("misdemeanorThreshold", ""), 0),
        "felonyThreshold": decode_uint(c.get("felonyThreshold", ""), 0),
        "felonySlashScope": decode_uint(c.get("felonySlashScope", ""), 0),
        "enableMaliciousVoteSlash": decode_uint(
            c.get("enableMaliciousVoteSlash", ""), 0),
        "downtimeSlashAmountBNB": (decode_uint(
            c.get("downtimeSlashAmount", ""), 0) or 0) / 10**18,
        "felonySlashAmountBNB": (decode_uint(
            c.get("felonySlashAmount", ""), 0) or 0) / 10**18,
        "downtimeJailTimeDays": (decode_uint(
            c.get("downtimeJailTime", ""), 0) or 0) / 86400,
        "felonyJailTimeDays": (decode_uint(
            c.get("felonyJailTime", ""), 0) or 0) / 86400,
    }
    return out


def run_plugin_live():
    """Run the real bnb_system_state plugin against mainnet."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                           / "backend"))
    import asyncio  # noqa: E402
    import httpx  # noqa: E402
    from app.plugins import bnb_system_state as bss  # noqa: E402
    from app.plugins.base import Ctx, Target  # noqa: E402
    from app.ratelimit import RateLimiter  # noqa: E402

    class NullCache:
        def get(self, *a, **k):
            return None

        def set(self, *a, **k):
            return None

    async def _main():
        async with httpx.AsyncClient(
                timeout=30, trust_env=False,
                proxy="http://hatch-egress-proxy:3128") as http:
            ctx = Ctx(run_id="bnb-live-probe", mode="passive",
                      http=http, cache=NullCache(), keys={},
                      limiter=RateLimiter(default_rps=5.0))
            plugin = bss.BnbSystemStatePlugin()
            target = Target(
                raw="bsc:0x0000000000000000000000000000000000001000",
                type="crypto_wallet")
            return await plugin.run(target, ctx)

    return asyncio.run(_main())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--testnet", action="store_true")
    ap.add_argument("--plugin", action="store_true",
                    help="also run the bnb_system_state plugin live")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    urls = TESTNET_RPCS if args.testnet else MAINNET_RPCS
    chain_id = 97 if args.testnet else 56
    out = probe(urls, chain_id)
    if args.plugin:
        res = run_plugin_live()
        out["plugin_run"] = {
            "status": str(res.status),
            "reason": res.reason,
            "findings": [
                {"key": f.key, "value": f.value,
                 "evidence": f.evidence} for f in res.findings],
        }
    default = (f"live_probes_{'chapel' if args.testnet else 'mainnet'}_"
               f"{time.strftime('%Y-%m-%d')}.json")
    path = Path(args.out or default)
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out["decoded"], indent=2))
    print("header deltas (s):", out["header_time_deltas_s"])
    print("latest ahead of local clock (s):",
          out["latest_block_ahead_of_local_s"])
    print("slash indicators:", out["slash_indicators_first3_mining"])
    if "plugin_run" in out:
        print("plugin findings:",
              [f["key"] for f in out["plugin_run"]["findings"]])
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
