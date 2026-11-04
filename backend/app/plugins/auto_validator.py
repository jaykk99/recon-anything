"""Auto-validator lane (2026-11-03, Jay's order).

Hand validation was the bottleneck of the whole recon funnel:
detectors produced thousands of candidates and a human (the parent
agent) re-read source, classified the recipient, probed from a
stranger address and checked balances one contract at a time. That
is how 3,148 findings ended up parked as UNVERIFIED.

This module is the machine replacement. validate_candidate() takes
a candidate finding plus whatever evidence lanes could gather and
returns exactly one verdict:

- VERIFIED_REAL: stranger receives, and a read-only stranger probe
  or a fork/local simulation PROVES it. Value stated.
- TRIGGER_ONLY: the code is real and ungated, but the value lands
  at a FIXED or HOLDER-SELF destination - a stranger can trigger
  it and receives $0. Token-authority findings (a mint/freeze
  authority held by one fixed issuer principal) land here with
  subclass TOKEN_RISK.
- FALSE_POSITIVE: killed by evidence - a gate found on the deep
  source read, a live stranger probe that reverts, a simulation
  where the stranger receives 0, or a contract balance of 0.
- UNVERIFIED: evidence is missing, and the verdict names exactly
  which piece (verified source / flagged function / recipient
  destination / stranger probe or simulation). Degraded or
  no-source candidates stay UNVERIFIED - they are never cleared
  by default.

Evidence gathered per candidate, in order:
1. Full verified-source gate read incl. modifiers and internal
   calls (contract_logic._gated_deep over _Scope).
2. Recipient classification (contract_logic.classify_recipient).
3. Read-only eth_call probes from the unfunded stranger
   0x00000000000000000000000000000000deaDBeef (contract_sim.eth_call).
4. Native balance read with time/source stamps.
5. Fork/local simulation where a lane provides one (the Part A
   fixture proof runs the vulnerable fixtures on a local anvil
   chain; the fuzz lane's fixed-harness confirmations feed the
   same slot).

Detection only: eth_call is a node-local simulation and cannot
change state; the local simulation runs on a throwaway chain.
No transaction is ever sent on a live chain, and no drain is ever
executed.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import time
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from . import contract_sim as sim

STRANGER = sim.FUZZ_CALLER  # 0x000...deaDBeef, unfunded by design

VERDICTS = ("VERIFIED_REAL", "TRIGGER_ONLY", "FALSE_POSITIVE",
            "UNVERIFIED")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _beneficiary_metered(fn: Dict[str, Any]) -> Optional[str]:
    """Is this function's payout metered by the RECEIVING
    address parameter's own recorded entitlement, and consumed?

    Looks for a mapping read keyed by an address parameter of
    the function (locked[holder], balances[to], ...) plus a
    write that consumes that same entry (decrement, zeroing,
    delete, or a consumed-flag set). Returns the mapping name
    when both are present, else None.
    """
    text = fn["text"]
    sig = fn["signature"]
    # Parameter list = up to the paren that closes the opening
    # one. (rindex(")") would run into the returns clause of a
    # multi-part signature and take the return value's name as
    # the last parameter - the FLY unlock shape.)
    try:
        start = sig.index("(")
    except ValueError:
        return None
    depth = 0
    end = None
    for i in range(start, len(sig)):
        if sig[i] == "(":
            depth += 1
        elif sig[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        return None
    inner = sig[start + 1:end]
    addr_params = []
    for part in inner.split(","):
        toks = part.strip().split()
        if len(toks) >= 2 and "address" in part:
            addr_params.append(toks[-1])
    # A consumption write on the keyed entry: a decrement, a
    # delete, or an assignment to the entry itself, to a nested
    # entry (locked[holder][reason]), or to one of its fields
    # (locked[holder][reason].claimed = true - the consumed-flag
    # shape). Comparisons (==, >=) must not count.
    nested = r"(?:\s*\[(?:[^[\]]|\[[^\]]*\])*\])*" \
             r"(?:\s*\.\w+)?"
    for param in addr_params:
        for m in re.finditer(
                r"([A-Za-z_]\w*)\s*\[\s*" + re.escape(param) +
                r"\s*\]", text):
            name = m.group(1)
            keyed = re.escape(name) + r"\s*\[\s*" + \
                re.escape(param) + r"\s*\]"
            if re.search(keyed + r"\s*(-=|\+=)", text) or \
                    re.search(keyed + nested + r"\s*=(?!=)",
                              text) or \
                    re.search(r"delete\s+" + keyed, text):
                return name
    return None


def _find_fn(source: str, name: str, contract_name: str = ""):
    scope = cl._Scope(source, contract_name)
    for fn in scope.functions:
        if fn["name"] == name and "{" in fn["text"]:
            return scope, fn
    return scope, None


def validate_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Machine verdict for one candidate finding.

    candidate keys (all optional except address/kind):
      address, chain, function, kind, detail,
      source (verified source text) or None,
      contract_name,
      recipient_override (for non-EVM lanes, e.g. Stacks/Clarity,
        where classify_recipient cannot parse the source),
      authority_class (True for token-authority findings: mint /
        freeze / delegate authority held by a fixed principal),
      probe: {"status": "success"|"revert"|"transport_error",
              "detail": str, "via": str},
      balances: {"native_wei": int|None, "observed_at": str,
                 "source": str},
      simulation: {"ran": bool, "stranger_received": number|None,
                   "unit": str, "detail": str},
      entitlement_metered: bool - payout amount is metered by the
        caller's own recorded entitlement, so an eth_call success
        alone cannot measure what a stranger would receive.
    """
    out: Dict[str, Any] = {
        "address": candidate.get("address", ""),
        "chain": candidate.get("chain", ""),
        "function": candidate.get("function", ""),
        "kind": candidate.get("kind", ""),
        "verdict": "UNVERIFIED",
        "reason": "",
        "recipient": None,
        "gated": None,
        "value": None,
        "missing": [],
        "evidence": {},
    }

    # Token-authority class: the power sits with one fixed issuer
    # principal. Not stranger-receivable by construction.
    if candidate.get("authority_class"):
        out["verdict"] = "TRIGGER_ONLY"
        out["subclass"] = "TOKEN_RISK"
        out["recipient"] = candidate.get("recipient_override",
                                         "FIXED")
        out["reason"] = (
            "token-authority finding: the flagged power (mint / "
            "freeze / delegate / metadata authority) is held by a "
            "fixed issuer principal; a stranger holds none of it "
            "and receives nothing. Token risk, not a "
            "stranger-receivable drain.")
        return out

    source = candidate.get("source") or ""
    probe = candidate.get("probe") or {}
    simulation = candidate.get("simulation") or {}
    balances = candidate.get("balances") or {}

    if not source and not candidate.get("recipient_override"):
        out["missing"] = ["verified source"]
        out["reason"] = ("no verified source available (fetch "
                         "failed or contract unverified); cannot "
                         "read the gate or the recipient")
        return out

    fn = None
    scope = None
    if source and candidate.get("function"):
        scope, fn = _find_fn(source, candidate["function"],
                             candidate.get("contract_name", ""))
        if fn is None:
            out["missing"] = ["flagged function in verified source"]
            out["reason"] = (
                f"function '{candidate['function']}' not found in "
                "the verified source for this contract")
            return out

    # 1. Gate read (deep: modifiers + internal calls).
    gated: Optional[bool] = None
    if fn is not None and scope is not None:
        gated = bool(cl._gated_deep(fn, scope))
    out["gated"] = gated

    # 2. Recipient classification.
    recipient = candidate.get("recipient_override")
    if recipient is None and fn is not None:
        recipient, rdetail = cl.classify_recipient(fn["text"])
        out["evidence"]["recipient_detail"] = rdetail
        if recipient == "CALLER-SUPPLIED":
            metered = _beneficiary_metered(fn)
            if metered:
                # The destination is a caller-supplied address,
                # but the payout is metered by THAT address's
                # own recorded entitlement and the entitlement
                # is consumed: the classic unlock(holder) /
                # release(holder) shape. The value belongs to
                # the beneficiary's own position - HOLDER-SELF,
                # not a stranger-receivable drain (the FLY
                # adjudication, Nov 2).
                out["evidence"]["beneficiary_metered"] = metered
                recipient = "HOLDER-SELF"
    out["recipient"] = recipient

    if recipient in ("FIXED", "HOLDER-SELF"):
        if gated:
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "gated: the deep source read finds an access "
                "gate on the flagged function, and its value "
                f"destination is {recipient} besides; a stranger "
                "can neither trigger it nor receive from it")
            return out
        if simulation.get("ran") and \
                float(simulation.get("stranger_received") or 0) > 0:
            out["missing"] = ["reconciliation of recipient read "
                              "vs simulation payout"]
            out["reason"] = (
                "source read classifies the destination as "
                f"{recipient}, but a simulation measured a "
                "stranger receiving value - the lanes disagree, "
                "so no verdict is forced")
            return out
        out["verdict"] = "TRIGGER_ONLY"
        out["reason"] = (
            f"ungated and triggerable by a stranger, but the "
            f"value destination is {recipient}; the stranger "
            "receives $0")
        return out
    if recipient in (None, "UNRESOLVED"):
        out["missing"] = ["recipient destination"]
        out["reason"] = ("no value destination could be "
                         "classified in the flagged function")
        return out

    # Recipient is CALLER / CALLER-SUPPLIED. Measured proof
    # outranks the static gate read: a simulation that moves
    # value to a stranger is ground truth, and one that moves
    # nothing kills the candidate even if the source read
    # thought the path was open (the gate read can misread
    # entitlement checks as gates and vice versa).
    if simulation.get("ran"):
        received = simulation.get("stranger_received")
        out["evidence"]["simulation"] = simulation.get("detail", "")
        if received is not None and float(received) > 0:
            out["verdict"] = "VERIFIED_REAL"
            out["value"] = (f"{received} "
                            f"{simulation.get('unit', '')}".strip())
            out["reason"] = (
                "fork/local simulation proves a stranger "
                f"receives {out['value']}; recipient "
                f"{recipient}")
            return out
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "fork/local simulation ran and the stranger "
            "received 0 - the payout does not reach a stranger "
            "in practice")
        return out

    if gated:
        if probe.get("status") == "success":
            out["missing"] = ["reconciliation of gate read vs "
                              "successful stranger probe"]
            out["reason"] = (
                "deep source read finds a gate on the flagged "
                "function, but a stranger probe succeeded - the "
                "two evidence lanes disagree, so no verdict is "
                "forced")
            return out
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "gated: the deep source read (function, modifiers "
            "and internal calls) finds an access gate on the "
            "flagged function; a stranger cannot call it")
        return out

    if probe.get("status") == "revert":
        out["verdict"] = "FALSE_POSITIVE"
        out["reason"] = (
            "live read-only probe from the unfunded stranger "
            f"reverts ({probe.get('detail', '')[:160]}); the "
            "source-level path is dead at live state")
        return out

    if probe.get("status") == "success":
        native = balances.get("native_wei")
        if native is not None and int(native) == 0:
            out["verdict"] = "FALSE_POSITIVE"
            out["reason"] = (
                "stranger probe succeeds but the contract holds "
                "0 native balance; there is nothing for a "
                "stranger to receive")
            return out
        if candidate.get("entitlement_metered"):
            out["missing"] = ["fork/local simulation (an "
                              "eth_call cannot measure a payout "
                              "metered by caller entitlement)"]
            out["reason"] = (
                "stranger probe succeeds, but the payout is "
                "metered by the caller's own recorded "
                "entitlement, so the amount a stranger would "
                "actually receive is unmeasured")
            return out
        out["verdict"] = "VERIFIED_REAL"
        if native is not None:
            out["value"] = f"contract native balance {native} wei (upper bound on the native payout)"
        out["reason"] = (
            "read-only probe from the unfunded stranger "
            "succeeds, the function is ungated, and the value "
            f"destination is {recipient}")
        return out

    out["missing"] = ["stranger probe or fork/local simulation"]
    out["reason"] = (
        "source read is candidate-grade (ungated, recipient "
        f"{recipient}) but no probe or simulation has run, so "
        "the payout is unproven")
    return out


# ---------------------------------------------------------------------------
# Live evidence gathering (used by the plugin wrapper)
# ---------------------------------------------------------------------------

async def _native_balance(ctx: Ctx, chain: cc.ChainConfig,
                          address: str) -> Dict[str, Any]:
    from ..ratelimit import fetch
    payload = {"jsonrpc": "2.0", "id": 1,
               "method": "eth_getBalance",
               "params": [address, "latest"]}
    routes = []
    if chain.blockscout_api:
        base = chain.blockscout_api.rsplit("/api", 1)[0]
        routes.append((f"{base}/api/eth-rpc", "Blockscout eth-rpc"))
    for rpc in chain.rpc_urls:
        routes.append((rpc, "public JSON-RPC"))
    for url, label in routes:
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url,
                            json=payload, timeout=10, max_retries=0)
            if r.status_code != 200:
                continue
            d = r.json()
        except Exception:
            continue
        if isinstance(d, dict) and isinstance(d.get("result"), str):
            try:
                wei = int(d["result"], 16)
            except Exception:
                continue
            return {"native_wei": wei, "observed_at": _now(),
                    "source": label}
    return {"native_wei": None, "observed_at": _now(),
            "source": "all routes failed"}


async def gather_and_validate(ctx: Ctx, key: Optional[str],
                              candidate: Dict[str, Any]
                              ) -> Dict[str, Any]:
    """Fetch source, probe and balances for one candidate, then
    run the pure verdict engine. Never sends a transaction."""
    chain_id = candidate.get("chain") or ""
    chain = cc.CHAINS.get(chain_id)
    addr = candidate.get("address", "")
    if chain is None or not cc.ADDRESS_RE.match(addr or ""):
        v = dict(candidate)
        v.update({"verdict": "UNVERIFIED",
                  "reason": "candidate has no resolvable EVM "
                            "chain/address for this lane",
                  "missing": ["EVM chain/address"]})
        return v
    src = await cc.fetch_verified_source(ctx, chain, addr, key)
    if src:
        candidate["source"] = src["source"]
        candidate["contract_name"] = src.get("contract_name", "")
    fn_name = candidate.get("function", "")
    if src and fn_name:
        scope, fn = _find_fn(src["source"], fn_name,
                             candidate.get("contract_name", ""))
        if fn is not None:
            types = sim._param_types(fn["signature"])
            if types is not None:
                cases = sim.boundary_cases(types, addr)
                probe = {"status": "transport_error",
                         "detail": "no probe case ran"}
                for case in cases[:3]:
                    data = sim.function_selector(
                        sim.canonical_signature(fn_name, types)) + \
                        (case["encoded"] or "")
                    res = await sim.eth_call(ctx, chain, addr, data,
                                             STRANGER)
                    probe = res
                    if res.get("status") in ("success", "revert"):
                        break
                candidate["probe"] = probe
    candidate["balances"] = await _native_balance(ctx, chain, addr)
    return validate_candidate(candidate)


# ---------------------------------------------------------------------------
# Plugin wrapper (heavy lane)
# ---------------------------------------------------------------------------

class AutoValidatorPlugin(Plugin):
    id = "auto_validator"
    label = "Auto Validator"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = (
        "Machine validation of candidate findings: deep gate "
        "read, recipient classification, read-only stranger "
        "probes, balance reads and simulation results folded "
        "into VERIFIED_REAL / TRIGGER_ONLY / FALSE_POSITIVE / "
        "UNVERIFIED verdicts with evidence.")
    phase = 2
    lane = "heavy"
    timeout_s = 600

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        candidates: List[Dict[str, Any]] = []
        for item in ctx.consume("validator_candidates"):
            if isinstance(item, dict) and item.get("address"):
                candidates.append(dict(item))
        if not candidates:
            # A bare contract target with no candidate queue has
            # nothing to validate in this lane.
            res = self._skipped(
                "auto_validator: no candidate findings queued on "
                "the discovery bus for this run (validator "
                "candidates are published under "
                "'validator_candidates')")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        counts: Dict[str, int] = {v: 0 for v in VERDICTS}
        for cand in candidates[:8]:
            try:
                verdict = await gather_and_validate(ctx, key, cand)
            except Exception as e:
                verdict = {"verdict": "UNVERIFIED",
                           "reason": f"validator error: {e}",
                           "address": cand.get("address", ""),
                           "function": cand.get("function", ""),
                           "kind": cand.get("kind", "")}
            counts[verdict["verdict"]] = \
                counts.get(verdict["verdict"], 0) + 1
            sev = {"VERIFIED_REAL": "high",
                   "TRIGGER_ONLY": "low",
                   "FALSE_POSITIVE": "low",
                   "UNVERIFIED": "medium"}[verdict["verdict"]]
            findings.append(self._f(
                "web3", "validator_verdict",
                f"{verdict['verdict']}: {verdict.get('address', '')} "
                f"{verdict.get('function', '')} - "
                f"{verdict.get('reason', '')}",
                source="auto-validator (source read + stranger "
                       "probe + balances)",
                confidence=90,
                evidence={"severity": sev, "verdict": verdict},
                passive=True))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            "auto_validator: " + ", ".join(
                f"{k}={v}" for k, v in counts.items()))
        res.duration_ms = dur
        return res
