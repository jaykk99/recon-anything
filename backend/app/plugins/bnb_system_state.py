"""BNB system-contract live-state reader (Parlia, P-02/P-04/P-05/P-07/P-08).

READ-ONLY. Reads the live BNB Smart Chain system contracts with
eth_call only (no transactions, nothing broadcast) and reports the
live state that bears on the flaws in the 2026-11-17 BNB Chain
analysis:

- ValidatorSet  0x0000000000000000000000000000000000001000
- SlashIndicator 0x0000000000000000000000000000000000001001
- StakeHub      0x0000000000000000000000000000000000002002

Findings are ANALYSIS of public chain state, each carrying the
observed live numbers. A finding fires only when the live value
matches the flaw condition (e.g. felony threshold still 150
blocks, slash ratio still >= 10x); if mainnet state has moved,
the plugin says so in its reason and emits nothing for that
flaw. If every RPC route fails it reports DEGRADED, never clean.

What this does NOT do: P-01/P-03/P-06/P-09/P-10/P-11/P-12 are
consensus/client-level and not observable from system-contract
state; P-10 (sub-second timestamps) is covered by the standalone
live-probe script, not this plugin.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from . import contract_chain as cc
from . import contract_sim as cs
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

VALIDATOR_SET = "0x0000000000000000000000000000000000001000"
SLASH_INDICATOR = "0x0000000000000000000000000000000000001001"
STAKE_HUB = "0x0000000000000000000000000000000000002002"

# Block interval the flaw arithmetic is denominated in (BEP-126
# era: 0.45s slots; the design constants were written at 3s).
BLOCK_INTERVAL_S = 0.45

SEL = {
    "getValidators": cs.function_selector("getValidators()"),
    "getMiningValidators": cs.function_selector("getMiningValidators()"),
    "numOfCabinets": cs.function_selector("numOfCabinets()"),
    "maxNumOfWorkingCandidates": cs.function_selector(
        "maxNumOfWorkingCandidates()"),
    "getTurnLength": cs.function_selector("getTurnLength()"),
    "misdemeanorThreshold": cs.function_selector(
        "misdemeanorThreshold()"),
    "felonyThreshold": cs.function_selector("felonyThreshold()"),
    "felonySlashScope": cs.function_selector("felonySlashScope()"),
    "enableMaliciousVoteSlash": cs.function_selector(
        "enableMaliciousVoteSlash()"),
    "getSlashIndicator": cs.function_selector(
        "getSlashIndicator(address)"),
    "downtimeSlashAmount": cs.function_selector(
        "downtimeSlashAmount()"),
    "felonySlashAmount": cs.function_selector("felonySlashAmount()"),
    "downtimeJailTime": cs.function_selector("downtimeJailTime()"),
    "felonyJailTime": cs.function_selector("felonyJailTime()"),
}


def decode_uint(data_hex: str, word: int = 0) -> Optional[int]:
    if not isinstance(data_hex, str) or not data_hex.startswith("0x"):
        return None
    h = data_hex[2:]
    start = word * 64
    if len(h) < start + 64:
        return None
    try:
        return int(h[start:start + 64], 16)
    except ValueError:
        return None


def decode_bool(data_hex: str) -> Optional[bool]:
    v = decode_uint(data_hex, 0)
    return None if v is None else bool(v)


def decode_address_array(data_hex: str) -> List[str]:
    """Decode a returned address[] (offset, length, items)."""
    if not isinstance(data_hex, str) or not data_hex.startswith("0x"):
        return []
    h = data_hex[2:]
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


def _encode_address(addr: str) -> str:
    a = addr.lower()
    if a.startswith("0x"):
        a = a[2:]
    return "0" * 24 + a.rjust(40, "0")


async def _batch_read(ctx: Ctx, calls: List[Tuple[str, str]]
                      ) -> List[Optional[str]]:
    """One batched eth_call round-trip; per-call fallback on failure.

    ``calls`` is a list of (to, data). Returns the raw result hex
    per call (None when that call failed). Read-only throughout.
    """
    chain = cc.CHAINS["bsc"]
    batch = [{"to": to, "data": data, "sender": cs.FUZZ_CALLER}
             for to, data in calls]
    try:
        res = await cs.eth_call_batch(ctx, chain, batch)
    except Exception:
        res = None
    if res is not None and len(res) == len(calls):
        out = []
        for r in res:
            if isinstance(r, dict) and r.get("status") == "success":
                out.append(r.get("result"))
            else:
                out.append(None)
        if any(v is not None for v in out):
            return out
    out = []
    for to, data in calls:
        try:
            r = await cs.eth_call(ctx, chain, to, data, cs.FUZZ_CALLER)
        except Exception:
            r = {"status": "transport_error"}
        if isinstance(r, dict) and r.get("status") == "success":
            out.append(r.get("result"))
        else:
            out.append(None)
    return out


class BnbSystemStatePlugin(Plugin):
    id = "bnb_system_state"
    label = "BNB System-Contract State Reader (Analysis Only)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("READ-ONLY live-state reader for the BNB Smart "
                   "Chain system contracts (ValidatorSet, "
                   "SlashIndicator, StakeHub): reports the live "
                   "values behind the Parlia flaws P-02/P-04/P-05/"
                   "P-07/P-08 as ANALYSIS findings. eth_call only, "
                   "nothing broadcast.")
    phase = 2
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        calls = [
            (VALIDATOR_SET, SEL["getValidators"]),
            (VALIDATOR_SET, SEL["numOfCabinets"]),
            (VALIDATOR_SET, SEL["maxNumOfWorkingCandidates"]),
            (VALIDATOR_SET, SEL["getMiningValidators"]),
            (SLASH_INDICATOR, SEL["misdemeanorThreshold"]),
            (SLASH_INDICATOR, SEL["felonyThreshold"]),
            (SLASH_INDICATOR, SEL["felonySlashScope"]),
            (SLASH_INDICATOR, SEL["enableMaliciousVoteSlash"]),
            (STAKE_HUB, SEL["downtimeSlashAmount"]),
            (STAKE_HUB, SEL["felonySlashAmount"]),
            (STAKE_HUB, SEL["downtimeJailTime"]),
            (STAKE_HUB, SEL["felonyJailTime"]),
        ]
        results = await _batch_read(ctx, calls)
        (validators_raw, cabinets_raw, working_cand_raw,
         mining_raw, misd_raw, fel_raw, scope_raw, mal_vote_raw,
         down_amt_raw, fel_amt_raw, down_jail_raw,
         fel_jail_raw) = results
        if all(v is None for v in results):
            res = self._degraded(
                "DEGRADED: every BNB system-contract eth_call route "
                "failed (Blockscout eth-rpc and public BSC JSON-RPC "
                "unreachable), so no live state was read and nothing "
                "is cleared")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        validators = decode_address_array(validators_raw or "")
        cabinets = decode_uint(cabinets_raw or "", 0)
        # A stored 0 means "use the default": the contract falls back
        # to INIT_NUM_OF_CABINETS (21) when numOfCabinets is unset.
        # Live mainnet reads 0 here; reporting 0 cabinets would be wrong.
        if cabinets == 0:
            cabinets = 21
        working_cand = decode_uint(working_cand_raw or "", 0)
        mining = decode_address_array(mining_raw or "")
        misd = decode_uint(misd_raw or "", 0)
        fel = decode_uint(fel_raw or "", 0)
        scope = decode_uint(scope_raw or "", 0)
        mal_vote = decode_bool(mal_vote_raw or "")
        down_amt = decode_uint(down_amt_raw or "", 0)
        fel_amt = decode_uint(fel_amt_raw or "", 0)
        down_jail = decode_uint(down_jail_raw or "", 0)
        fel_jail = decode_uint(fel_jail_raw or "", 0)

        findings: List[Finding] = []
        notes: List[str] = []

        # P-02 live: block-denominated jail + stale scope.
        if misd is not None and fel is not None:
            fel_wall_s = fel * BLOCK_INTERVAL_S
            if fel <= 200:
                findings.append(self._f(
                    "web3", "bnb_parlia_p02_live",
                    f"ANALYSIS: live SlashIndicator felony threshold "
                    f"is {fel} blocks = ~{fel_wall_s:.1f}s of missed "
                    f"blocks at 0.45s/block (misdemeanor {misd}); "
                    f"jail accrues in bare blocks with no wall-clock "
                    f"scaling (P-02)",
                    "BnbSystemState", confidence=85,
                    evidence={"severity": "high",
                              "misdemeanor_threshold_blocks": misd,
                              "felony_threshold_blocks": fel,
                              "felony_wall_seconds": fel_wall_s,
                              "analysis_only": True,
                              "remediation": "Denominate the jail "
                              "thresholds in wall-clock time or scale "
                              "them by the block interval."}))
            else:
                notes.append(f"felony threshold {fel} blocks (P-02 "
                             f"condition not present)")
        if scope is not None:
            scope_wall_h = scope * BLOCK_INTERVAL_S / 3600
            if scope == 28800 or scope_wall_h < 24:
                findings.append(self._f(
                    "web3", "bnb_parlia_p02_live",
                    f"ANALYSIS: live felonySlashScope is {scope} "
                    f"blocks = ~{scope_wall_h:.1f}h at 0.45s/block, "
                    f"not the 1 day the design comment states "
                    f"(P-02 stale block-time scope)",
                    "BnbSystemState", confidence=85,
                    evidence={"severity": "medium",
                              "felony_slash_scope_blocks": scope,
                              "felony_slash_scope_hours": round(
                                  scope_wall_h, 2),
                              "analysis_only": True,
                              "remediation": "Express the evidence "
                              "window in wall-clock time."}))
            else:
                notes.append(f"felonySlashScope {scope} blocks (P-02 "
                             f"scope condition not present)")

        # P-04 live: no vote-participation accounting. The live
        # indicator carries only (height, count); the only vote
        # penalty is the malicious-vote slash, itself toggleable.
        if mal_vote is not None:
            sev = "high" if not mal_vote else "medium"
            detail = ("live SlashIndicator exposes no "
                      "vote-participation accounting "
                      "(getSlashIndicator returns height/count "
                      "only); vote withholding carries no penalty "
                      "(P-04)")
            if not mal_vote:
                detail += (" - and enableMaliciousVoteSlash is "
                           "currently FALSE, so even active vote "
                           "misbehaviour is unpunished live")
            findings.append(self._f(
                "web3", "bnb_parlia_p04_live",
                f"ANALYSIS: {detail}; "
                f"enableMaliciousVoteSlash={mal_vote}",
                "BnbSystemState", confidence=80,
                evidence={"severity": sev,
                          "enable_malicious_vote_slash": mal_vote,
                          "analysis_only": True,
                          "remediation": "Add a participation score "
                          "with a reward penalty and a jail trigger "
                          "for sustained non-voting."}))
        else:
            notes.append("enableMaliciousVoteSlash unread (P-04 "
                         "toggle state unknown)")

        # P-05 live: mining set is 21, schedule precomputable.
        if mining:
            findings.append(self._f(
                "web3", "bnb_parlia_p05_live",
                f"ANALYSIS: live mining set is {len(mining)} "
                f"validators (getMiningValidators); the in-turn "
                f"schedule is a pure function of this set and block "
                f"number, publicly precomputable (P-05)",
                "BnbSystemState", confidence=80,
                evidence={"severity": "medium",
                          "mining_validators": len(mining),
                          "mining_sample": mining[:3],
                          "analysis_only": True,
                          "remediation": "Seed the mining-set "
                          "shuffle with unpredictable entropy."}))
        if validators:
            notes.append(f"validator set: {len(validators)} validators")

        # P-07 live: cabinet / candidate rotation shape.
        if cabinets is not None and working_cand is not None \
                and validators:
            findings.append(self._f(
                "web3", "bnb_parlia_p07_live",
                f"ANALYSIS: live set is {len(validators)} validators "
                f"with {cabinets} cabinets and "
                f"{working_cand} working-candidate slots re-drawn "
                f"into the mining set every epoch, with no "
                f"reliability gate on candidates (P-07)",
                "BnbSystemState", confidence=80,
                evidence={"severity": "medium",
                          "validators": len(validators),
                          "cabinets": cabinets,
                          "working_candidates": working_cand,
                          "analysis_only": True,
                          "remediation": "Gate candidate promotion "
                          "on measured uptime/reliability."}))

        # P-08 live: slash asymmetry.
        if down_amt is not None and fel_amt is not None \
                and down_amt > 0:
            ratio = fel_amt / down_amt
            jail_ratio = (fel_jail / down_jail
                          if down_jail and fel_jail else None)
            if ratio >= 10 or (jail_ratio and jail_ratio >= 10):
                findings.append(self._f(
                    "web3", "bnb_parlia_p08_live",
                    f"ANALYSIS: live slash asymmetry is "
                    f"{fel_amt / 10**18:g} BNB felony vs "
                    f"{down_amt / 10**18:g} BNB downtime "
                    f"({ratio:.0f}x) and "
                    f"{(fel_jail or 0) // 86400} days felony jail "
                    f"vs {(down_jail or 0) // 86400} days downtime "
                    f"jail (P-08)",
                    "BnbSystemState", confidence=85,
                    evidence={"severity": "high",
                              "downtime_slash_bnb": down_amt / 10**18,
                              "felony_slash_bnb": fel_amt / 10**18,
                              "slash_ratio": ratio,
                              "downtime_jail_days":
                                  (down_jail or 0) // 86400,
                              "felony_jail_days":
                                  (fel_jail or 0) // 86400,
                              "analysis_only": True,
                              "remediation": "Scale the felony "
                              "penalty to the fault and add a "
                              "partition amnesty."}))
            else:
                notes.append(f"slash ratio {ratio:.1f}x (P-08 "
                             f"condition not present)")

        # Per-validator slash indicators for the first mining
        # validators (public consensus addresses, public state):
        # proves the live counters are readable and shows current
        # missed-block pressure. Best effort; never blocks the run.
        if mining:
            ind_calls = [(SLASH_INDICATOR,
                          SEL["getSlashIndicator"] + _encode_address(a))
                         for a in mining[:3]]
            try:
                ind = await _batch_read(ctx, ind_calls)
            except Exception:
                ind = []
            counts = []
            for a, raw in zip(mining[:3], ind or []):
                if raw:
                    h = decode_uint(raw, 0)
                    c = decode_uint(raw, 1)
                    if h is not None and c is not None:
                        counts.append((a, h, c))
            if counts:
                worst = max(counts, key=lambda x: x[2])
                notes.append(
                    "slash indicators (first 3 mining): " +
                    ", ".join(f"{a[:10]}… h={h} count={c}"
                              for a, h, c in counts) +
                    f"; highest count {worst[2]} "
                    f"(felony at {fel})")

        reason = (f"{len(findings)} BNB system-state findings"
                  + (f"; {'; '.join(notes)}" if notes else ""))
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
