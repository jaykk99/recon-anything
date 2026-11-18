"""Devnet PoCs for the BNB Chain analysis (2026-11-17) on a local
anvil fork of Chapel testnet (chain 97).

WRITE-LEVEL, FORK-ONLY. Every state-changing call runs against a
local anvil fork of Chapel (no mainnet broadcasts, no real funds,
no real validators harmed - fork state is discarded). The fork is
pinned at block 143179354 (Chapel, via publicnode) and started
with:

    anvil --fork-url https://bsc-testnet-rpc.publicnode.com \\
          --fork-block-number 143179354 --chain-id 97 --port 8545

PoCs:
- P-05: replicate the ValidatorSet mining-set shuffle in Python
  (keccak256(abi.encodePacked(shuffleNumber, idx)) % mod) and
  show it reproduces getMiningValidators exactly at the fork
  block and after mining across a shuffle boundary.
- P-07: mine across 200-block shuffle boundaries and count
  mining-set rotation (candidate slot churn).
- P-02/P-08: impersonate the fork block's coinbase and call
  SlashIndicator.slash() once per block for one Chapel validator;
  Chapel thresholds are misdemeanor 333 / felony 1000 (same as
  mainnet live). Observe the misdemeanor at 333, the felony +
  downtime slash at 1000, the 10 BNB stake deduction and the
  jailing (voting power -> 0). This proves the block-counted jail
  mechanics and the 20x/15x asymmetry end to end.

Usage:
    python3 pocs/bnb/devnet_poc.py [--rpc URL] [--out FILE]
      [--slashes N] [--target ADDR]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx
from Crypto.Hash import keccak

VALIDATOR_SET = "0x0000000000000000000000000000000000001000"
SLASH_INDICATOR = "0x0000000000000000000000000000000000001001"
STAKE_HUB = "0x0000000000000000000000000000000000002002"

SEL = {
    "getValidators": "b7ab4db5",
    "getMiningValidators": "4df6e0c3",
    "numOfCabinets": "7a84ca2a",
    "maxNumOfWorkingCandidates": "f92eb86b",
    "getTurnLength": "8c5d749d",
    "misdemeanorThreshold": "567a372d",
    "felonyThreshold": "389f4f71",
    "felonySlashScope": "9f804f5f",
    "enableMaliciousVoteSlash": "22d1e80b",
    "getSlashIndicator": "37c8dab9",
    "downtimeSlashAmount": "d8ca511f",
    "felonySlashAmount": "bdceadf3",
    "getValidatorElectionInfo": "63a036b5",
}

try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                           / "backend"))
    from app.plugins.contract_sim import function_selector as _fs
    SEL["isCurrentValidator"] = _fs("isCurrentValidator(address)")[2:]
    SEL["slash"] = _fs("slash(address)")[2:]
except Exception:
    SEL["slash"] = "7d7b3a23"  # replaced at runtime if helper missing


def k256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def enc_u256(n: int) -> bytes:
    return n.to_bytes(32, "big")


class Rpc:
    def __init__(self, url: str):
        self.url = url
        # Local fork: no proxy. trust_env=False avoids the
        # malformed proxy var that breaks httpx env parsing.
        self.c = httpx.Client(timeout=120, trust_env=False)
        self._id = 0

    def call(self, method: str, params):
        self._id += 1
        last_err = None
        for attempt in range(3):
            try:
                r = self.c.post(
                    self.url,
                    json={"jsonrpc": "2.0", "id": self._id,
                          "method": method, "params": params})
                r.raise_for_status()
                d = r.json()
            except Exception as e:  # noqa: BLE001 - retry
                last_err = e
                time.sleep(2 * (attempt + 1))
                continue
            if "error" in d:
                raise RuntimeError(f"{method}: {d['error']}")
            return d["result"]
        raise last_err

    def eth_call(self, to: str, data: str, block="latest"):
        return self.call("eth_call", [{"to": to, "data": data}, block])

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)


def dec_u(hexstr: str, word: int = 0):
    if not isinstance(hexstr, str) or not hexstr.startswith("0x"):
        return None
    h = hexstr[2:]
    s = word * 64
    if len(h) < s + 64:
        return None
    return int(h[s:s + 64], 16)


def dec_addrs(hexstr: str):
    if not isinstance(hexstr, str) or not hexstr.startswith("0x"):
        return []
    h = hexstr[2:]
    if len(h) < 128:
        return []
    off = int(h[0:64], 16)
    n = int(h[off * 2:off * 2 + 64], 16)
    out = []
    base = off * 2 + 64
    for i in range(min(n, 200)):
        chunk = h[base + i * 64: base + (i + 1) * 64]
        if len(chunk) < 64:
            break
        out.append("0x" + chunk[24:64])
    return out


def shuffle_replica(validators, vote_addrs, shuffle_number,
                    start_idx, offset, limit, mod_number):
    """Exact replica of BSCValidatorSet.shuffle()."""
    vals = list(validators)
    adds = list(vote_addrs)
    for i in range(limit):
        rnd = int.from_bytes(
            k256(enc_u256(shuffle_number) + enc_u256(start_idx + i)),
            "big") % mod_number
        if (start_idx + i) != (offset + rnd):
            vals[start_idx + i], vals[offset + rnd] = \
                vals[offset + rnd], vals[start_idx + i]
            adds[start_idx + i], adds[offset + rnd] = \
                adds[offset + rnd], adds[start_idx + i]
    return vals, adds


def mining_set_replica(rpc: Rpc, block: int):
    """Reproduce getMiningValidators at `block` in pure Python."""
    blk = hex(block)
    vals = dec_addrs(rpc.eth_call(VALIDATOR_SET,
                                  "0x" + SEL["getValidators"], blk))
    mining_hex = rpc.eth_call(VALIDATOR_SET,
                              "0x" + SEL["getMiningValidators"], blk)
    h = mining_hex[2:]
    off2 = int(h[64:128], 16)
    onchain_mining = dec_addrs(mining_hex)
    n_vote = int(h[off2 * 2:off2 * 2 + 64], 16)
    cabinets = dec_u(rpc.eth_call(
        VALIDATOR_SET, "0x" + SEL["numOfCabinets"], blk), 0) or 21
    working = dec_u(rpc.eth_call(
        VALIDATOR_SET, "0x" + SEL["maxNumOfWorkingCandidates"], blk), 0)
    if len(vals) <= cabinets:
        return onchain_mining, list(vals), cabinets, working, n_vote
    vote_addrs = [f"vote{i}" for i in range(len(vals))]
    shuffle_number = block // 200
    v1, _ = shuffle_replica(vals, vote_addrs, shuffle_number,
                            cabinets - working, 0, working, cabinets)
    v2, _ = shuffle_replica(v1, vote_addrs, shuffle_number,
                            cabinets - working, cabinets - working,
                            working, len(vals) - cabinets + working)
    return onchain_mining, v2[:cabinets], cabinets, working, n_vote


def get_indicator(rpc: Rpc, addr: str):
    data = "0x" + SEL["getSlashIndicator"] + "0" * 24 + addr[2:]
    res = rpc.eth_call(SLASH_INDICATOR, data)
    return {"height": dec_u(res, 0), "count": dec_u(res, 1)}


def voting_power(rpc: Rpc, addr: str):
    """totalPooledBNB for one validator via getValidatorElectionInfo."""
    data = ("0x" + SEL["getValidatorElectionInfo"]
            + "%064x" % 0 + "%064x" % 0)
    res = rpc.eth_call(STAKE_HUB, data)
    h = res[2:]
    o1, o2 = int(h[0:64], 16), int(h[64:128], 16)
    n = int(h[o1 * 2:o1 * 2 + 64], 16)
    addrs = []
    base = o1 * 2 + 64
    for i in range(n):
        addrs.append("0x" + h[base + i * 64 + 24:base + (i + 1) * 64])
    pbase = o2 * 2 + 64
    powers = [int(h[pbase + i * 64:pbase + (i + 1) * 64], 16)
              for i in range(n)]
    for a, p in zip(addrs, powers):
        if a.lower() == addr.lower():
            return p / 10**18
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--out", default=None)
    ap.add_argument("--slashes", type=int, default=1000)
    ap.add_argument("--target", default=None,
                    help="validator to slash (default: first mining)")
    ap.add_argument("--skip-slash", action="store_true",
                    help="run P-05/P-07 only, no slash loop")
    args = ap.parse_args()
    rpc = Rpc(args.rpc)
    out = {"fork_block": rpc.block_number(), "chain_id": 97}
    print(f"fork at block {out['fork_block']}")

    # ---- baseline state -------------------------------------------
    vals = dec_addrs(rpc.eth_call(VALIDATOR_SET,
                                  "0x" + SEL["getValidators"]))
    mining = dec_addrs(rpc.eth_call(VALIDATOR_SET,
                                    "0x" + SEL["getMiningValidators"]))
    cabinets = dec_u(rpc.eth_call(VALIDATOR_SET,
                                  "0x" + SEL["numOfCabinets"]), 0) or 21
    working = dec_u(rpc.eth_call(
        VALIDATOR_SET, "0x" + SEL["maxNumOfWorkingCandidates"]), 0)
    turn = dec_u(rpc.eth_call(VALIDATOR_SET,
                              "0x" + SEL["getTurnLength"]), 0)
    misd = dec_u(rpc.eth_call(SLASH_INDICATOR,
                              "0x" + SEL["misdemeanorThreshold"]), 0)
    fel = dec_u(rpc.eth_call(SLASH_INDICATOR,
                             "0x" + SEL["felonyThreshold"]), 0)
    scope = dec_u(rpc.eth_call(SLASH_INDICATOR,
                               "0x" + SEL["felonySlashScope"]), 0)
    mal = dec_u(rpc.eth_call(SLASH_INDICATOR,
                             "0x" + SEL["enableMaliciousVoteSlash"]), 0)
    down_amt = dec_u(rpc.eth_call(STAKE_HUB,
                                  "0x" + SEL["downtimeSlashAmount"]), 0)
    fel_amt = dec_u(rpc.eth_call(STAKE_HUB,
                                 "0x" + SEL["felonySlashAmount"]), 0)
    out["baseline"] = {
        "validators": len(vals), "mining_validators": len(mining),
        "numOfCabinets": cabinets, "maxNumOfWorkingCandidates": working,
        "turnLength": turn, "misdemeanorThreshold": misd,
        "felonyThreshold": fel, "felonySlashScope": scope,
        "enableMaliciousVoteSlash": mal,
        "downtimeSlashAmountBNB": (down_amt or 0) / 10**18,
        "felonySlashAmountBNB": (fel_amt or 0) / 10**18,
    }
    print("baseline:", json.dumps(out["baseline"]))

    # ---- P-05: shuffle replica at fork block + after mining ---------
    blk0 = out["fork_block"]
    onchain, replica, cab, work, nvote = mining_set_replica(rpc, blk0)
    out["p05"] = {"block": blk0,
                  "onchain_mining": onchain,
                  "replica_mining": replica,
                  "match_at_fork_block": onchain == replica,
                  "cabinets": cab, "working_candidates": work,
                  "vote_addrs": nvote}
    print(f"P-05 at fork block {blk0}: replica match = "
          f"{out['p05']['match_at_fork_block']}")
    if onchain != replica:
        print("  onchain:", onchain[:3], "...")
        print("  replica:", replica[:3], "...")

    # ---- P-07: rotation across shuffle boundaries -------------------
    # Mine in 200-block steps and sample the mining set at each
    # boundary; the set is a function of block.number // 200.
    samples = []
    cur = blk0
    samples.append({"block": cur, "mining": onchain})
    for step in range(3):
        rpc.call("anvil_mine", [200, 0])
        cur = rpc.block_number()
        m = dec_addrs(rpc.eth_call(
            VALIDATOR_SET, "0x" + SEL["getMiningValidators"]))
        samples.append({"block": cur, "mining": m})
        print(f"P-07 mined to {cur}: mining set changed = "
              f"{m != samples[-2]['mining']}")
    changes = []
    for a, b in zip(samples, samples[1:]):
        sa, sb = set(a["mining"]), set(b["mining"])
        changes.append({"from_block": a["block"], "to_block": b["block"],
                        "entered": sorted(sb - sa),
                        "left": sorted(sa - sb),
                        "changed_count": len(sb - sa) + len(sa - sb)})
    out["p07"] = {"samples": samples, "changes": changes,
                  "shuffle_interval_blocks": 200}
    for c in changes:
        print(f"P-07 {c['from_block']}->{c['to_block']}: "
              f"{c['changed_count']} slots changed "
              f"(entered {len(c['entered'])}, left {len(c['left'])})")

    # P-05 again at the final block (after rotation).
    onchain2, replica2, _, _, _ = mining_set_replica(rpc, cur)
    out["p05"]["match_after_mining"] = onchain2 == replica2
    out["p05"]["final_block"] = cur
    print(f"P-05 at block {cur}: replica match = "
          f"{out['p05']['match_after_mining']}")

    # ---- P-02 / P-08: slash loop (fork only) ------------------------
    if args.skip_slash:
        out["p02_p08"] = {"skipped": True}
    else:
        target = args.target or mining[0]
        print(f"P-02/P-08 target validator: {target}")
        # Anvil mines new blocks with coinbase 0x0 (verified
        # first-hand: an anvil_mine block's miner is the zero
        # address), and slash() is onlyCoinbase - so the sender
        # must be 0x0, not the fork head's miner.
        coinbase = "0x0000000000000000000000000000000000000000"
        print(f"anvil block coinbase (impersonating): {coinbase}")
        rpc.call("anvil_impersonateAccount", [coinbase])
        rpc.call("anvil_setBalance",
                 [coinbase, "0x56BC75E2D63100000"])  # 100 ETH for gas
        before_ind = get_indicator(rpc, target)
        before_power = voting_power(rpc, target)
        out["p02_p08"] = {
            "target": target, "coinbase": coinbase,
            "thresholds": {"misdemeanor": misd, "felony": fel},
            "before": {"indicator": before_ind,
                       "voting_power_bnb": before_power},
            "observations": [],
        }
        print(f"  before: indicator={before_ind} "
              f"voting_power={before_power} BNB")
        slash_data = "0x" + SEL["slash"] + "0" * 24 + target[2:]
        # Trial slash: prove the call path works (right sender,
        # right modifiers) before committing to the loop. Gas must
        # be 500k: the first slash on a cold fork slot costs more
        # than 100k and reverts out-of-gas.
        tx0 = {"from": coinbase, "to": SLASH_INDICATOR,
               "data": slash_data, "gas": "0x7a120", "gasPrice": "0x0"}
        txh0 = rpc.call("eth_sendTransaction", [tx0])
        # The receipt can lag the send by a moment on a fork;
        # poll briefly instead of trusting the first read.
        rec0 = None
        for _ in range(20):
            rec0 = rpc.call("eth_getTransactionReceipt", [txh0])
            if rec0 is not None:
                break
            time.sleep(0.5)
        ind0 = get_indicator(rpc, target)
        print(f"  trial slash: tx={txh0} status={rec0.get('status')} "
              f"indicator={ind0}")
        if rec0.get("status") != "0x1" or ind0["count"] != \
                (before_ind["count"] or 0) + 1:
            raise SystemExit(
                "trial slash did not land (receipt status "
                f"{rec0.get('status')}, indicator {ind0}) - aborting "
                "the loop rather than sending 1000 no-ops")
        n = min(args.slashes, fel) if fel else args.slashes
        # The trial slash already counts as slash #1.
        sent = 1
        milestones = {misd, fel} if (misd and fel) else set()
        t0 = time.time()
        for i in range(2, n + 1):
            tx = {"from": coinbase, "to": SLASH_INDICATOR,
                  "data": slash_data, "gas": "0x7a120",
                  "gasPrice": "0x0"}
            try:
                txh = rpc.call("eth_sendTransaction", [tx])
                sent = i
            except Exception as e:
                out["p02_p08"]["observations"].append(
                    {"slash": i, "error": str(e)[:200]})
                print(f"  slash {i} FAILED: {e}")
                break
            if i in milestones or i % 250 == 0:
                ind = get_indicator(rpc, target)
                power = voting_power(rpc, target)
                out["p02_p08"]["observations"].append(
                    {"slash": i, "tx": txh, "indicator": ind,
                     "voting_power_bnb": power,
                     "block": rpc.block_number()})
                print(f"  slash {i}: indicator={ind} "
                      f"voting_power={power} BNB "
                      f"({time.time() - t0:.0f}s elapsed)")
        after_ind = get_indicator(rpc, target)
        after_power = voting_power(rpc, target)
        out["p02_p08"]["after"] = {"indicator": after_ind,
                                   "voting_power_bnb": after_power}
        out["p02_p08"]["slashes_sent"] = sent
        out["p02_p08"]["elapsed_s"] = round(time.time() - t0, 1)
        print(f"  after {sent} slashes: indicator={after_ind} "
              f"voting_power={after_power} BNB")

    default = (f"devnet_poc_chapel_"
               f"{time.strftime('%Y-%m-%d')}.json")
    path = Path(args.out or default)
    path.write_text(json.dumps(out, indent=2))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
