"""Deep-audit detectors, batch 22: claim guards, checkpoints, decimals.

Five chain-agnostic EVM detectors from the 2026-11-15 research
(CodeHawks Snarkeling, Firelight Immunefi #89588/#89014, Hacken
TCG-Vault F-2026-19272, DSCEngine / Inverse FiRM, Rhea Finance),
built to the batch-19 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- claim_guard_wrong_key_replay: a claim/payout function whose
  already-claimed guard reads a mapping keyed by a state /
  immutable variable that is never assigned anywhere in the
  contract (so it permanently reads the zero key), while the
  mark function writes claimed[<parameter key>] = true. Guard
  key != mark key, so one valid proof replays until the pool
  drains - the CodeHawks Snarkeling TreasureHunt shape
  (#3/#28/#150/#183/#202). The guard and mark keys being the
  same expression, or the guard variable being assigned in the
  constructor, is the protected shape. Distinct from built
  claim_callback_before_claimed_flag (flag set AFTER the
  callback - a timing shape, not a wrong-key shape) and
  recipient_unbacked_claim (no backing at all, not a guard-key
  mismatch).
- checkpoint_overwrite_equal_key_rewrites_snapshot: a
  checkpoint library push that OVERWRITES on key == last key,
  PLUS a permissionless withdraw that pushes a checkpoint at a
  period-boundary key, PLUS a payout/capacity consumer reading
  that key as a cap - the Firelight Immunefi #89588/#89014
  shape. The library-overwrite semantics is the distinguishing
  element vs built period_start_checkpoint_zeroes_payout_cap
  (deep_audit21, #88287: inclusive lookup + min-cap
  conjunction, which does not read the library
  implementation). An append-only push (revert on equal key,
  or plain append) is the protected shape; a withdraw that
  pushes a boundary checkpoint through an append-only library
  stays silent here.
- presale_hardcoded_decimals_dust_purchase: a sale/buy/presale
  function computing the token allocation from a payment amount
  using a hardcoded 1e6 / 10**6 scaling constant while never
  reading the payment token's decimals() and with no per-token
  decimal config - the Hacken TCG-Vault F-2026-19272 shape, so
  the whole round is purchasable for dust when the payment
  token does not have 6 decimals. Reading decimals(), or
  pinning the payment token to an allowlisted stablecoin, is
  the protected shape. Distinct from built
  hardcoded_decimals_scaling (1e18 literals only).
- collateral_value_assumes_18_decimals: a collateral
  USD-valuation function that reads a price feed
  (latestRoundData), scales the price by a hardcoded 1e10 /
  1e18 factor, multiplies by a token amount, NEVER reads the
  collateral token's decimals(), and feeds a health-factor /
  borrow-limit / liquidation computation - the DSCEngine
  CodeHawks #1/#800 shape (1 WBTC at $60,000 valued at
  ~$0.000006; Inverse FiRM shipped the same misconfiguration
  live). A per-token decimals mapping, or a decimals() read,
  is the protected shape. Beats the generic
  hardcoded_decimals_scaling slice by requiring the
  oracle-price + health-factor/borrow conjunction.
- permissionless_collateral_listing_fake_token: a collateral /
  market listing function (addCollateral / addMarket /
  listToken / supportAsset) that is permissionless (no
  owner/governance gate) OR accepts a caller-supplied price
  feed/oracle with no allowlist check, combined with a borrow
  function consuming that collateral's price - the Rhea
  Finance Apr 2026 shape (~$7.6M: counterfeit tokens listed
  as collateral, real USDC/USDT/ZEC/NEAR borrowed against
  the inflated fake-token value). A gated listing, or a
  caller-supplied oracle that must pass an allowlist, is the
  protected shape. Distinct from built
  lending_collateral_price_provider_unvalidated (the provider
  ADDRESS spoofable from caller input at valuation time);
  this is the LISTING side.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding on the permissionless entry point - a stranger cannot
reach the path. The payout consumer in the checkpoint
detector is exempt by design (it is privileged; the bug is
the state corruption the permissionless withdraw performs),
and the valuation function in the decimals detector is
exempt (it is view; the borrow consumer is the gated check).

Detection only: verified-source static analysis in the fast
lane, never sends a transaction, never calls the contract
for value. Fetch failure is reported honestly by the shared
scaffolding (analyzed 0 / no verified source - skipped),
never dressed up as a clean result.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from .bsc_common import DetectorSpec, S

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deep22"

SPECS = [
    S("claim_guard_wrong_key_replay", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Claim guard reads the wrong key, so the replay "
             "guard never fires: a claim/payout function checks "
             "an already-claimed mapping keyed by a state / "
             "immutable variable that is never assigned anywhere "
             "in the contract (so it permanently reads the zero "
             "key), while the mark function writes "
             "claimed[<parameter key>] = true. Guard key != mark "
             "key, so one valid proof replays until the pool "
             "drains and the value goes to a caller-supplied "
             "recipient - the CodeHawks Snarkeling TreasureHunt "
             "shape. The guard and mark keys being the same "
             "expression, or the guard variable being assigned "
             "in the constructor, is the protected shape.",
      fix="Key the already-claimed guard by the same value the "
          "mark writes: require(!claimed[treasureHash]) where "
          "treasureHash is the claim function's parameter (not "
          "an unassigned state variable), and assign any "
          "immutable guard key in the constructor. Mark claimed "
          "before the external transfer."),
    S("checkpoint_overwrite_equal_key_rewrites_snapshot",
      FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Checkpoint overwrite on equal key rewrites the "
             "period snapshot: the checkpoint library's push "
             "OVERWRITES the last entry when the new key equals "
             "the last key, a permissionless withdraw pushes a "
             "checkpoint at a period-boundary key, and a payout "
             "/ capacity consumer reads that same key as its "
             "cap - so a withdraw mined at the period boundary "
             "rewrites the snapshot the allocator already "
             "consumed, and an approved claim is short-paid "
             "while the withdrawer keeps the shortfall - the "
             "Firelight Immunefi #89588/#89014 shape. An "
             "append-only push (revert on equal key, or plain "
             "append) is the protected shape.",
      fix="Make the checkpoint push append-only: revert (or "
          "append a new entry) when the new key equals the last "
          "key, never overwrite the last entry in place. Size "
          "the period's sellable cover from a snapshot taken "
          "after the period boundary, not from a key a "
          "permissionless withdraw can rewrite."),
    S("presale_hardcoded_decimals_dust_purchase", FAMILY,
      severity="high",
      outcome="a", recipient=True,
      detail="Presale buys allocation for dust via hardcoded "
             "stablecoin decimals: a sale/buy/presale function "
             "computes the token allocation from a payment "
             "amount using a hardcoded 1e6 / 10**6 scaling "
             "constant while never reading the payment token's "
             "decimals() and with no per-token decimal config - "
             "so the whole round is purchasable for dust when "
             "the payment token does not have 6 decimals - the "
             "Hacken TCG-Vault F-2026-19272 shape. Reading "
             "decimals(), or pinning the payment token to an "
             "allowlisted 6-decimal stablecoin, is the "
             "protected shape.",
      fix="Read the payment token's decimals() (or a per-token "
          "decimals config) and scale the allocation by "
          "10**decimals instead of a hardcoded 1e6. If the "
          "round is stablecoin-only, enforce an allowlist of "
          "6-decimal payment tokens."),
    S("collateral_value_assumes_18_decimals", FAMILY,
      severity="high",
      outcome="a", recipient=True,
      detail="Collateral valuation assumes 18 decimals for "
             "every token: a collateral USD-valuation function "
             "reads a price feed (latestRoundData), scales the "
             "price by a hardcoded 1e10 / 1e18 factor, "
             "multiplies by a token amount, NEVER reads the "
             "collateral token's decimals(), and feeds a "
             "health-factor / borrow-limit / liquidation "
             "computation - so an 8-decimal token like WBTC is "
             "underpriced 1e10, liquidations underflow and "
             "revert, and bad debt builds unchecked - the "
             "DSCEngine CodeHawks #1/#800 shape (Inverse FiRM "
             "shipped the same misconfiguration live). A "
             "per-token decimals mapping, or a decimals() read, "
             "is the protected shape.",
      fix="Scale the valuation by the collateral token's own "
          "decimals: read token.decimals() (or a per-token "
          "decimals config) and divide by 10**decimals "
          "instead of assuming 18. Never hardcode the 1e10 "
          "price-feed precision for every collateral token."),
    S("permissionless_collateral_listing_fake_token", FAMILY,
      severity="high",
      outcome="a", recipient=True,
      detail="Permissionless collateral listing admits a "
             "fake-token collateral: a collateral/market "
             "listing function (addCollateral / addMarket / "
             "listToken / supportAsset) is permissionless (no "
             "owner/governance gate) OR accepts a "
             "caller-supplied price feed/oracle with no "
             "allowlist check, and a borrow function consumes "
             "that collateral's price - so a stranger lists a "
             "counterfeit token with a seeded price history as "
             "collateral and borrows real assets against its "
             "inflated value - the Rhea Finance Apr 2026 shape "
             "(~$7.6M). A gated listing, or a caller-supplied "
             "oracle that must pass an allowlist, is the "
             "protected shape.",
      fix="Gate collateral/market listing behind owner or "
          "governance, and allowlist both the collateral token "
          "and its price feed: never accept a caller-supplied "
          "token or oracle without an explicit allowlist "
          "check. Validate the token is a real asset with "
          "real liquidity before it can back borrows."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 19 / deep19)
# ---------------------------------------------------------------------------

def _scope_fns(src: str, contract_name: str):
    scope = cl._Scope(src, contract_name)
    fns = [fn for fn in scope.functions if "{" in fn["text"]]
    return scope, fns


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str, gate: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail,
            "gate_analysis": gate}


def _classify(item: Dict[str, Any], recipient: str,
              rdetail: str) -> Dict[str, Any]:
    """The Nov 2 receive rule, carried on the finding."""
    item["recipient"] = recipient
    if recipient in ("FIXED", "HOLDER-SELF"):
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: the value / power lands at "
            f"a {recipient} destination ({rdetail}), so a "
            "stranger can trigger this but receives nothing - "
            "classified TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"
        item["detail"] += (
            f" Recipient analysis: recipient classified "
            f"{recipient} ({rdetail}) - a stranger can receive "
            f"value or control here, classified CANDIDATE under "
            f"the receive rule.")
    return item


def _finish_recipient(spec: DetectorSpec, item: Dict[str, Any],
                      fn_text: str) -> Dict[str, Any]:
    recipient, rdetail = cl.classify_recipient(fn_text)
    return _classify(item, recipient, rdetail)


def _finish_recipient_meter_broken(
        spec: DetectorSpec, item: Dict[str, Any], fn_text: str,
        meter_note: str) -> Dict[str, Any]:
    """HOLDER-SELF -> CALLER when the bug breaks the meter.

    The Nov 14 meter-broken rule (first used by the batch-21
    oracle detector): the shared classifier reads a payout
    bounded by the caller's own recorded position as
    HOLDER-SELF, but when the bug itself breaks that meter -
    the meter bounds the payout by a value the bug distorts -
    the caller receives value beyond what the meter should
    allow, so the finding upgrades to CALLER. FIXED stays
    FIXED (trigger-only): the meter-broken rule never
    upgrades a fixed destination.
    """
    recipient, rdetail = cl.classify_recipient(fn_text)
    if recipient == "HOLDER-SELF":
        item["detail"] += (
            f" Recipient analysis: the shared classifier reads "
            f"this as HOLDER-SELF (the payout is bounded by "
            f"the caller's own recorded position), but the bug "
            f"breaks that meter itself - {meter_note} - so the "
            f"caller receives value beyond what the meter "
            f"should allow. Upgraded to CALLER under the Nov "
            f"14 meter-broken rule.")
        return _classify(item, "CALLER",
                         rdetail + "; meter broken by the bug")
    return _classify(item, recipient, rdetail)


_IDENTITY_GATE_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses.
    """
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or _IDENTITY_GATE_RE.search(text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and ("msg.sender" in body and
                         ("==" in body or "!=" in body)):
                return True
    return False


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
    return text[open_pos + 1:], len(text)


def _split_top(text: str) -> List[str]:
    depth = 0
    parts: List[str] = []
    cur: List[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _fn_params(fn: Dict[str, Any]) -> List[str]:
    """Parameter names from a function signature."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append(toks[-1])
    return out


def _fn_param_addrs(fn: Dict[str, Any]) -> List[str]:
    """Address-typed parameter names from a function signature."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        if "address" not in part:
            continue
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append(toks[-1])
    return out


def _moves_value(text: str) -> bool:
    """A token transfer / ETH call / send in the function."""
    if re.search(r"\.(transfer|transferFrom|send|call)\s*"
                 r"(\{|\(|\.)", text):
        return True
    if re.search(r"\.call\s*\{[^}]*value\s*:", text):
        return True
    return False


# ---------------------------------------------------------------------------
# 1. claim_guard_wrong_key_replay
# ---------------------------------------------------------------------------

_CLAIM_FN_RE = re.compile(
    r"(claim|payout|redeem|withdraw|treasure|hunt)", re.I)
# A mapping read keyed by one identifier, e.g. claimed[_treasureHash].
_MAP_READ_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*\]")
# The mark write: claimed[<expr>] = true (any key expression).
_MARK_WRITE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]\s*=\s*true\b")


def _never_assigned_vars(scoped: str, state: set) -> set:
    """State variables with no assignment anywhere in the scope.

    A declaration initializer counts as an assignment (the
    variable holds a real value), so a var declared as
    `bytes32 private immutable _treasureHash;` with no `=`
    anywhere is never assigned - the Snarkeling shape.
    """
    out = set()
    for name in state:
        if re.search(r"\b" + re.escape(name) +
                     r"\s*(?:\[[^\]]*\])?\s*(?:\+=|-=|\*=|/=|"
                     r"=(?!=))", scoped):
            continue
        out.add(name)
    return out


def _guard_conditions(text: str) -> List[str]:
    """Condition strings of require(...) / if (...) in the text."""
    conds: List[str] = []
    for m in re.finditer(r"\b(?:require|if)\s*\(", text):
        open_pos = m.end() - 1
        inner, _ = _balanced(text, open_pos)
        conds.append(inner)
    return conds


def _analyze_claim_guard(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    never_assigned = _never_assigned_vars(scoped, state)
    if not never_assigned:
        return []
    # The mark writes, anywhere in the contract: map name ->
    # set of key expressions written with `= true`.
    marks: Dict[str, set] = {}
    for m in _MARK_WRITE_RE.finditer(scoped):
        marks.setdefault(m.group(1), set()).add(
            re.sub(r"\s+", "", m.group(2)))
    if not marks:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _CLAIM_FN_RE.search(fn["name"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        if not _moves_value(text):
            continue
        for cond in _guard_conditions(text):
            for m in _MAP_READ_RE.finditer(cond):
                map_name, key = m.group(1), m.group(2)
                if key not in never_assigned:
                    continue
                if map_name not in marks:
                    continue
                # Guard key == mark key means the guard works.
                if re.sub(r"\s+", "", key) in marks[map_name]:
                    continue
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' guards the "
                    f"claim with {map_name}[{key}], but "
                    f"'{key}' is a state variable that is "
                    f"never assigned anywhere in the contract "
                    f"(so the guard permanently reads the zero "
                    f"key), while the mark writes "
                    f"{map_name}[<parameter>] = true with a "
                    f"different key - the guard and the mark "
                    f"never intersect, so one valid proof "
                    f"replays until the pool drains. Gate "
                    f"analysis: no caller-identity gate on the "
                    f"claim path.")
                item = _hit(spec, fn["name"], cc._snip(text),
                            detail,
                            "ungated claim: already-claimed guard "
                            "reads an unassigned state variable, "
                            "mark writes a different key")
                out.append(_finish_recipient(spec, item, text))
                break
    return out


# ---------------------------------------------------------------------------
# 2. checkpoint_overwrite_equal_key_rewrites_snapshot
# ---------------------------------------------------------------------------

_WITHDRAW_FN_RE = re.compile(r"(withdraw|exit|redeem)", re.I)
_PAYOUT_FN_RE = re.compile(
    r"(payout|claim|assess|cover|allocat)", re.I)
_CHECKPOINT_LOOKUP_RE = re.compile(
    r"\b(?:upperLookup|lowerLookup|lookup|latestCheckpoint)\s*\(")
_OVERWRITE_ASSIGN_RES = (
    # The last entry's value overwritten in place.
    re.compile(r"\.\s*(?:_value|value)\s*=(?!=)"),
    # The whole last entry overwritten.
    re.compile(r"\[\s*[A-Za-z_]\w*\s*-\s*1\s*\]\s*=(?!=)"),
    re.compile(r"\[\s*len\s*-\s*1\s*\]\s*=(?!=)"),
    re.compile(r"\[\s*_len\s*-\s*1\s*\]\s*=(?!=)"),
)


def _push_overwrites_on_equal_key(fn: Dict[str, Any]
                                 ) -> Optional[str]:
    """The push function overwrites on key == last key, or None.

    Returns the key parameter name when the push body has an
    `if (... == ...)` condition comparing the key parameter
    against the last entry's key, followed by an overwrite
    assignment to the last entry. An append-only push (revert
    on equal key, or plain append) has no such overwrite and
    returns None - that is the #88287-shape distinction.
    """
    text = fn["text"]
    params = _fn_params(fn)
    key_param = None
    for p in params:
        if p.lower() in ("key", "_key", "newkey", "new_key"):
            key_param = p
            break
    if key_param is None:
        key_param = "key"
    for m in re.finditer(r"\bif\s*\(", text):
        open_pos = m.end() - 1
        cond, end = _balanced(text, open_pos)
        if "==" not in cond:
            continue
        if not re.search(r"\b" + re.escape(key_param) + r"\b",
                         cond):
            continue
        if not re.search(r"\blast\b|prev|-\s*1\s*\]|length",
                         cond):
            continue
        # The equal-key branch must overwrite the last entry,
        # not revert: look for an overwrite assignment in the
        # rest of the function body after this condition.
        rest = text[end:end + 600]
        # A revert inside the branch means append-only.
        if re.search(r"\brevert\b", rest[:120]):
            continue
        if any(p.search(rest) for p in _OVERWRITE_ASSIGN_RES):
            return key_param
    return None


def _analyze_checkpoint_overwrite(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Leg A: the library push overwrites on equal key.
    push_fn = None
    for fn in fns:
        if "push" not in fn["name"].lower():
            continue
        if _push_overwrites_on_equal_key(fn):
            push_fn = fn
            break
    if push_fn is None:
        return []
    # Leg B: a permissionless withdraw pushing a checkpoint at
    # a period-boundary key, moving value to the caller.
    withdraw_fn = None
    for fn in fns:
        if not _WITHDRAW_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        if not re.search(
                r"\.push\s*\([^)]*(period|start|timestamp)|"
                r"\bpush\s*\([^)]*(period|start|timestamp)",
                text):
            continue
        if not _moves_value(text):
            continue
        withdraw_fn = fn
        break
    if withdraw_fn is None:
        return []
    # Leg C: a payout / capacity consumer reading that key as
    # a cap (checkpoint lookup + min / cap use).
    payout_fn = None
    for fn in fns:
        if not _PAYOUT_FN_RE.search(fn["name"]):
            continue
        text = fn["text"]
        if not _CHECKPOINT_LOOKUP_RE.search(text):
            continue
        if (re.search(r"\bmin\s*\(", text) or
                re.search(r"\bcap\b", text, re.I) or
                re.search(r"<=|>=|Math\.min", text)):
            payout_fn = fn
            break
    if payout_fn is None:
        return []
    detail = spec.detail + (
        f" Observed: checkpoint push '{push_fn['name']}' "
        f"overwrites the last entry when the new key equals "
        f"the last key; permissionless '{withdraw_fn['name']}' "
        f"pushes a checkpoint at a period-boundary key; and "
        f"'{payout_fn['name']}' reads that key as its payout "
        f"cap (checkpoint lookup + min/cap use) - so a "
        f"withdraw mined at the period boundary rewrites the "
        f"snapshot the allocator already consumed. Gate "
        f"analysis: the withdraw is permissionless (no "
        "caller-identity gate); the payout consumer is "
        "privileged by design, the corruption is done by the "
        "withdrawer.")
    item = _hit(spec, withdraw_fn["name"],
                cc._snip(withdraw_fn["text"]), detail,
                "ungated withdraw pushes a period-boundary "
                "checkpoint through an equal-key-overwriting "
                "push; payout reads the same key as its cap")
    return [_finish_recipient_meter_broken(
        spec, item, withdraw_fn["text"],
        "the deposit balance is not the entitlement meter "
        "once a claim is assessed: the snapshot overwrite "
        "breaks the assessment reservation, and the "
        "withdrawer retains value earmarked for the approved "
        "claim (Firelight: the withdrawer retains "
        "560,000,000,000 of the 700,000,000,000-unit "
        "shortfall)")]


# ---------------------------------------------------------------------------
# 3. presale_hardcoded_decimals_dust_purchase
# ---------------------------------------------------------------------------

_BUY_FN_RE = re.compile(
    r"(buy|purchase|presale|sale)", re.I)
_SIX_DEC_RE = re.compile(
    r"\b1e6\b|10\s*\*\*\s*6\b|\b1000000\b|\b1_000_000\b")
_DECIMALS_CALL_RE = re.compile(r"\.decimals\s*\(")
_PER_TOKEN_DECIMALS_RE = re.compile(
    r"(tokenDecimals|collateralDecimals|assetDecimals|"
    r"paymentDecimals|decimals)\s*\[")
_ALLOWLIST_CHECK_RE = re.compile(
    r"(accepted|allowed|supported|approved|whitelisted)"
    r"[A-Za-z0-9_]*\s*\[[^\]]*\]")


def _analyze_presale_decimals(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Contract-level suppressions: the payment token's
    # decimals are read, or a per-token decimals config exists.
    if _DECIMALS_CALL_RE.search(scoped):
        return []
    if _PER_TOKEN_DECIMALS_RE.search(scoped):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BUY_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if _caller_gated(fn, scope):
            continue
        text = fn["text"]
        if not _SIX_DEC_RE.search(text):
            continue
        # The allocation is computed from a payment amount.
        if "msg.value" not in text and not re.search(
                r"\b(amount|payment|paymentAmount|usdtAmount|"
                r"stableAmount)\b", text):
            continue
        if "*" not in text and "/" not in text:
            continue
        # The payment token is pinned to an allowlisted
        # stablecoin: the dust path is closed.
        if _ALLOWLIST_CHECK_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' computes the token "
            f"allocation from the payment amount with a "
            f"hardcoded 1e6 scaling constant and never reads "
            f"the payment token's decimals() (no decimals() "
            f"call and no per-token decimals config anywhere "
            f"in the contract), so a payment token without 6 "
            f"decimals buys the round for dust. Gate analysis: "
            f"no caller-identity gate, no allowlist pinning "
            f"the payment token.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated sale: hardcoded 1e6 scaling, no "
                    "decimals() read, no per-token decimals "
                    "config, no payment-token allowlist")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. collateral_value_assumes_18_decimals
# ---------------------------------------------------------------------------

_PRICE_FEED_RE = re.compile(
    r"\blatestRoundData\s*\(|\blatestAnswer\s*\(")
_TEN_EIGHTEEN_RE = re.compile(
    r"\b1e10\b|\b1e18\b|10\s*\*\*\s*10\b|10\s*\*\*\s*18\b|"
    r"\b10000000000\b|\b1000000000000000000\b")
_AMOUNT_ID_RE = re.compile(
    r"\b(amount|collateralAmount|tokenAmount|balance|"
    r"quantity|collateral)\b")
_HEALTH_BORROW_RE = re.compile(
    r"(health|borrow|liquidat|collateral|account)", re.I)


def _analyze_collateral_decimals(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    # Contract-level suppressions: the collateral token's
    # decimals are read, or a per-token decimals config exists.
    if _DECIMALS_CALL_RE.search(scoped):
        return []
    if _PER_TOKEN_DECIMALS_RE.search(scoped):
        return []
    # The valuation function: oracle price + hardcoded 1e10 /
    # 1e18 scaling + multiplication by a token amount.
    val_fn = None
    for fn in fns:
        text = fn["text"]
        if not _PRICE_FEED_RE.search(text):
            continue
        if not _TEN_EIGHTEEN_RE.search(text):
            continue
        if not _AMOUNT_ID_RE.search(text):
            continue
        if "*" not in text:
            continue
        val_fn = fn
        break
    if val_fn is None:
        return []
    # The consumer: a health-factor / borrow-limit /
    # liquidation function that (transitively) calls the
    # valuation function, or the valuation function itself
    # is such a consumer.
    consumer_fn = None
    if _HEALTH_BORROW_RE.search(val_fn["name"]):
        consumer_fn = val_fn
    else:
        # Call graph: fn name -> fn names called in its body.
        by_name = {fn["name"]: fn for fn in fns}
        callees: Dict[str, set] = {}
        for fn in fns:
            called = set()
            for other in by_name:
                if other == fn["name"]:
                    continue
                if re.search(r"\b" + re.escape(other) +
                             r"\s*\(", fn["text"]):
                    called.add(other)
            callees[fn["name"]] = called

        def _reaches(start: str, target: str,
                     depth: int = 3) -> bool:
            seen = {start}
            frontier = {start}
            for _ in range(depth):
                nxt = set()
                for name in frontier:
                    for callee in callees.get(name, set()):
                        if callee == target:
                            return True
                        if callee not in seen:
                            seen.add(callee)
                            nxt.add(callee)
                frontier = nxt
            return False

        consumers = [fn for fn in fns
                     if fn is not val_fn
                     and _HEALTH_BORROW_RE.search(fn["name"])
                     and _reaches(fn["name"], val_fn["name"])]
        # The borrow path must be reachable by a stranger.
        ungated = [fn for fn in consumers
                   if not _caller_gated(fn, scope)]
        if not ungated:
            return []
        moving = [fn for fn in ungated
                  if _moves_value(fn["text"])]
        consumer_fn = (moving or ungated)[0]
    # The borrow path must be reachable by a stranger.
    if consumer_fn is not val_fn and \
            _caller_gated(consumer_fn, scope):
        return []
    detail = spec.detail + (
        f" Observed: valuation '{val_fn['name']}' reads the "
        f"price feed (latestRoundData), scales by a hardcoded "
        f"1e10/1e18 factor and multiplies by the token amount, "
        f"with no decimals() read and no per-token decimals "
        f"config anywhere in the contract; '{consumer_fn['name']}' "
        f"consumes that valuation for a health-factor / "
        f"borrow / liquidation computation - so an 8-decimal "
        f"collateral token is misvalued 1e10. Gate analysis: "
        f"the valuation is view; the borrow/health consumer "
        f"is permissionless.")
    item = _hit(spec, val_fn["name"], cc._snip(val_fn["text"]),
                detail,
                "ungated borrow/health consumer over a "
                "valuation that assumes 18 decimals, no "
                "decimals() read, no per-token decimals config")
    return [_finish_recipient_meter_broken(
        spec, item, consumer_fn["text"],
        "the health-factor meter is fed by the misvalued "
        "collateral: the meter bounds the borrow by a "
        "collateral value that is wrong 1e10, so the borrower "
        "receives value beyond what the meter should allow "
        "(DSCEngine: 1 WBTC at $60,000 valued at ~$0.000006)")]


# ---------------------------------------------------------------------------
# 5. permissionless_collateral_listing_fake_token
# ---------------------------------------------------------------------------

_LISTING_FN_RE = re.compile(
    r"(add|list|support|register|enable|set)"
    r"(Collateral|Market|Token|Asset)", re.I)
_CONFIG_WRITE_RE = re.compile(
    r"(collateral|market|supported|listed|allowed|approved)"
    r"[A-Za-z0-9_]*\s*(?:\[[^\]]*\]\s*=(?!=)|\.push\s*\()",
    re.I)
_PRICE_READ_RE = re.compile(
    r"latestRoundData\s*\(|latestAnswer\s*\(|getPrice\s*\(|"
    r"priceFeed|oracle|getUsdValue\s*\(")
_ORACLE_PARAM_RE = re.compile(
    r"(oracle|priceFeed|feed)", re.I)


def _analyze_listing_fake_token(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # The borrow consumer: a borrow function that consumes the
    # collateral's price.
    borrow_fn = None
    for fn in fns:
        if "borrow" not in fn["name"].lower():
            continue
        if _PRICE_READ_RE.search(fn["text"]):
            borrow_fn = fn
            break
    if borrow_fn is None:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LISTING_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        # The listing must take a caller-supplied token.
        if not _fn_param_addrs(fn):
            continue
        # The listing must write the collateral/market config.
        if not _CONFIG_WRITE_RE.search(text):
            continue
        gated = _caller_gated(fn, scope)
        # Caller-supplied oracle with no allowlist check: the
        # oracle parameter must pass an allowlist/approved
        # mapping read in this function to count as checked.
        oracle_param = None
        for p in _fn_params(fn):
            if _ORACLE_PARAM_RE.search(p):
                oracle_param = p
                break
        oracle_unchecked = False
        if oracle_param is not None:
            oracle_unchecked = not re.search(
                r"(allowlist|whitelist|approved|allowed|"
                r"accepted)[A-Za-z0-9_]*\s*\[\s*" +
                re.escape(oracle_param) + r"\s*\]", text)
        if gated and not oracle_unchecked:
            continue
        detail = spec.detail + (
            f" Observed: listing '{fn['name']}' "
            f"{'is permissionless (no owner/governance gate)' if not gated else 'accepts a caller-supplied oracle with no allowlist check'} "
            f"and writes the collateral/market config, while "
            f"'{borrow_fn['name']}' borrows against that "
            f"collateral's price - so a stranger lists a "
            f"counterfeit token as collateral and borrows real "
            f"assets against its inflated value. Gate "
            f"analysis: the listing has no caller-identity "
            f"gate (or no oracle allowlist); the borrow "
            f"consumes the listed collateral's price.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated collateral listing + borrow "
                    "consuming the listed collateral's price")
        out.append(_finish_recipient(spec, item,
                                     borrow_fn["text"]))
    return out


ANALYZERS = {
    "claim_guard_wrong_key_replay": _analyze_claim_guard,
    "checkpoint_overwrite_equal_key_rewrites_snapshot":
        _analyze_checkpoint_overwrite,
    "presale_hardcoded_decimals_dust_purchase":
        _analyze_presale_decimals,
    "collateral_value_assumes_18_decimals":
        _analyze_collateral_decimals,
    "permissionless_collateral_listing_fake_token":
        _analyze_listing_fake_token,
}


def analyze_deep22_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-22 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep22_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit22Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 19)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = ""
    phase = 2
    timeout_s = 120
    _spec: Optional[DetectorSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        work = self._collect(target, ctx)
        if not work or spec is None:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. bsc:0x...) "
                "or a web target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        analyzed = 0
        no_source = 0
        pairs_done = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs, got = await self._scan_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs, got = 0, False
            pairs_done += pairs
            if pairs:
                analyzed += 1
                if not got:
                    no_source += 1
        dur = int((time.monotonic() - t0) * 1000)
        hits = sum(1 for f in findings if f.key == spec.id)
        res = self._ok(
            findings,
            f"{spec.id}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - skipped, no "
            f"guess made), {hits} finding(s)")
        res.duration_ms = dur
        return res

    def _collect(self, target: Target,
                 ctx: Ctx) -> List[Tuple[Optional[str], str]]:
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            out.append((chain_hint, addr))

        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(chain_hint, addr)
                break
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(hint if isinstance(hint, str) and
                    hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return out[:MAX_ADDRESSES]

    async def _scan_address(self, ctx: Ctx, key: Optional[str],
                            chain_hint: Optional[str], addr: str,
                            findings: List[Finding]
                            ) -> Tuple[int, bool]:
        if chain_hint:
            chain_ids = [chain_hint]
        else:
            chain_ids = list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        got_source = False
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            pairs += 1
            if await self._scan_on_chain(ctx, key, chain, addr,
                                         code, findings):
                got_source = True
            if chain_hint:
                break
        return pairs, got_source

    async def _scan_on_chain(self, ctx: Ctx, key: Optional[str],
                             chain: cc.ChainConfig, addr: str,
                             code_hex: str,
                             findings: List[Finding]) -> bool:
        src = await cc.fetch_verified_source(ctx, chain, addr, key)
        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await cc.resolve_implementation(
                ctx, chain, addr, code_hex,
                {"implementation": (src or {}).get(
                    "implementation", "")})
        except Exception:
            pass
        impl = res.get("implementation") or ""
        role = "proxy_shell" if impl else "standalone"
        got = self._analyze_contract(chain, addr, src, findings,
                                     role=role, impl_addr=impl)
        if not impl:
            return got
        impl_code = None
        impl_src = None
        try:
            impl_code = await cc.rpc_get_code(ctx, chain, impl)
            impl_src = await cc.fetch_verified_source(
                ctx, chain, impl, key)
        except Exception:
            impl_code, impl_src = None, None
        if not impl_code or impl_code == "0x" or len(impl_code) < 4:
            return got
        return self._analyze_contract(
            chain, impl, impl_src, findings,
            role="implementation", proxy_addr=addr) or got

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "") -> bool:
        spec = self._spec
        if spec is None or not src:
            return False
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id,
                   "contract_role": role}
        if role == "implementation":
            base_ev["proxy_address"] = proxy_addr
            base_ev["implementation_address"] = addr
            tag = f" [implementation behind proxy {proxy_addr}]"
        elif role == "proxy_shell":
            base_ev["proxy_address"] = addr
            base_ev["implementation_address"] = impl_addr
            tag = f" [proxy shell; implementation {impl_addr}]"
        else:
            tag = ""
        for item in analyze_deep22_source(
                src["source"], spec, src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
            ev = dict(base_ev)
            ev.update({
                "severity": item["severity"],
                "check": spec.id,
                "kind": spec.id,
                "detector_outcome": spec.outcome,
                "function": item["function"],
                "code": item["code"],
                "detail": item["detail"],
                "bytecode_only": False,
                "source_origin": src.get("origin", ""),
                "contract_name": src.get("contract_name", ""),
                "remediation": spec.fix,
            })
            if item.get("report_class"):
                ev["report_class"] = item["report_class"]
                ev["recipient"] = item.get("recipient", "")
            if item.get("gate_analysis"):
                ev["gate_analysis"] = item["gate_analysis"]
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="deep audit detector batch 22 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit22Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 22) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
