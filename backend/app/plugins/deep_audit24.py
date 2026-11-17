"""Deep-audit detectors, batch 24: sell-hook reserve sync, escape-hatch
inputs, LP mint trust, bridge value binding, merkle leaf index.

Five chain-agnostic EVM detectors from the standing backlog queue,
built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- token_sell_hook_burns_pair_reserves_sync: a token transfer /
  hook path (_transfer / _beforeTokenTransfer / sell hook) that
  burns tokens held by an AMM pair (_burn(pair, ...) /
  burn(pair, ...)) and/or calls pair.sync() / IUniswapV2Pair
  .sync() BEFORE the transfer's own token movement completes
  (the balance credit / token transfer that settles the
  transfer). Burning pair-held tokens and syncing reserves
  mid-sell reprices the pool against the seller's remaining
  tokens, so the subsequent swap drains the pair - the Tendril
  shape (BNB Chain, 2026-11-05, ~$555k). A burn / sync that
  happens only after the full transfer settles is the protected
  shape, as is a plain transfer with no pair interaction at
  all. Distinct from callback_token_cei_violation (batch 14,
  hook re-enters accounting): this is reserve desync, not
  reentrancy.
- escape_hatch_unbound_public_inputs: an escapeHatch /
  emergencyWithdraw / escape function that transfers value
  sized by caller-supplied proof / output parameters (proofId,
  publicOutput / publicInputs, numRealTxs or equivalent) with
  NO proof verification on the path (no verifyProof / Merkle
  check / state-root binding / numRealTxs consistency check).
  The caller chooses the public inputs, so they choose the
  payout - the Aztec RollupProcessorV3 shape (Nov 2026,
  ~$2.2M + ~$2.15M). A verifyProof(...) / state-root check
  before the payout is the protected shape.
- lp_mint_unverified_caller_supplied: a removeLiquidity /
  withdraw function that takes the LP / share token address as
  a caller parameter and sizes the payout from THAT token's
  supply / balance (lpToken.totalSupply() /
  IERC20(lpToken).balanceOf(...)) instead of the pool's own
  stored LP supply, with no check binding the parameter to the
  pool's LP token. A forged mint with supply 1 passes the
  proportion checks and withdraws ~100% of the reserves - the
  Raydium legacy AMM V3 shape (~$1.34M). Reading the LP token
  from pool storage, or require(lpToken == storedLpToken), is
  the protected shape.
- bridge_release_value_unbound_to_proof: a bridge release /
  mint function that DOES verify a message hash / signature /
  proof (verification PRESENT - ecrecover / ECDSA.recover /
  verifySignature) and then transfers / mints a caller- or
  message-supplied amount with NO lookup comparing that amount
  to a deposit / lock / burn record for the transfer id (no
  deposits[txId].amount read, no lockedAmounts read, no
  value-equality require). A verified hash over a fake
  withdrawal still pays the full caller-chosen amount - the
  Verus-Ethereum bridge shape (May 2026, ~$11.58M, repeated
  Jul 2026, ~$7.5M). require(amount ==
  deposits[txId].amount) is the protected shape, and the
  function must be bridge-shaped (a release / unlock /
  transfer-execution name, a transfer / message identifier
  parameter, or a bridge contract): a plain public mint that
  verifies an allowlist proof and charges the caller per token
  is a paid mint, not a bridge release. Distinct
  from bridge_replay_unbound_digest (identity binding: the
  digest omits chain / origin / nonce), from
  bridge_wrapped_token_mint_unbacked (no gate at all), and
  from bridge_withdrawer_identity_spoof (the RECIPIENT is
  unbound, not the amount). A release with no verification at
  all is bridge_message_payload_injection's shape, not this
  one.
- merkle_proof_unbounded_leaf_index: a proof-verification
  function taking a leaf index (and proof) that verifies the
  proof (MerkleProof.verify / verifyCalldata / processProof)
  but NEVER checks the index against the tree / leaf count
  (no require(index < leafCount / treeSize / totalLeaves), no
  bounds check on the index anywhere on the path). An
  out-of-bounds leaf verifies as valid and confers the
  privileges of a real leaf - the Hyperbridge shape (Apr
  2026, ~$2.5M). require(index < leafCount) is the protected
  shape. Distinct from merkle_claim_no_claimed_marker (batch
  20, the claimed marker is absent entirely) and from
  merkle_proof_bypass_test (proof-length only, no leaf-index
  bound anywhere in its analyze()).

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path.

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
FAMILY = "deep24"

SPECS = [
    S("token_sell_hook_burns_pair_reserves_sync", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Token sell hook burns pair reserves and syncs "
             "mid-transfer: a token transfer / hook path "
             "(_transfer / _beforeTokenTransfer / sell hook) "
             "burns tokens held by an AMM pair (_burn(pair, "
             "...)) and/or calls pair.sync() BEFORE the "
             "transfer's own token movement completes (the "
             "balance credit / token transfer that settles "
             "the transfer), so the pool reprices against the "
             "seller's remaining tokens and the subsequent "
             "swap drains the pair - the Tendril shape (BNB "
             "Chain, 2026-11-05, ~$555k). A burn / sync that "
             "happens only after the full transfer settles "
             "is the protected shape, as is a plain transfer "
             "with no pair interaction at all.",
      fix="Never touch pair reserves mid-transfer: move the "
          "burn / sync to after the transfer fully settles "
          "(balances updated, tokens moved), or remove the "
          "pair-reserve burn from the transfer hook entirely "
          "and sync reserves only in the pool's own swap / "
          "mint / burn entry points."),
    S("escape_hatch_unbound_public_inputs", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Escape hatch pays out on unbound public inputs: "
             "an escapeHatch / emergencyWithdraw / escape "
             "function transfers value sized by "
             "caller-supplied proof / output parameters "
             "(proofId, publicOutput / publicInputs, "
             "numRealTxs or equivalent) with NO proof "
             "verification on the path (no verifyProof / "
             "Merkle check / state-root binding / numRealTxs "
             "consistency check), so the caller chooses the "
             "public inputs and therefore the payout - the "
             "Aztec RollupProcessorV3 shape (Nov 2026, "
             "~$2.2M + ~$2.15M). A verifyProof(...) / "
             "state-root check before the payout is the "
             "protected shape.",
      fix="Bind the escape-hatch payout to a verified proof: "
          "verify the proof against the committed state root "
          "(verifyProof / state-root check) and derive the "
          "payout from the verified public inputs only, "
          "reverting when verification fails or the "
          "numRealTxs count does not match the proof."),
    S("lp_mint_unverified_caller_supplied", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Liquidity removal trusts a caller-supplied LP "
             "mint: a removeLiquidity / withdraw function "
             "takes the LP / share token address as a caller "
             "parameter and sizes the payout from THAT "
             "token's supply / balance (lpToken.totalSupply "
             "() / IERC20(lpToken).balanceOf(...)) instead "
             "of the pool's own stored LP supply, with no "
             "check binding the parameter to the pool's LP "
             "token, so a forged mint with supply 1 passes "
             "the proportion checks and withdraws ~100% of "
             "the reserves - the Raydium legacy AMM V3 shape "
             "(~$1.34M). Reading the LP token from pool "
             "storage, or require(lpToken == storedLpToken), "
             "is the protected shape.",
      fix="Never trust a caller-supplied LP mint: read the LP "
          "token from pool storage, or require(lpToken == "
          "storedLpToken) before sizing any payout, and size "
          "the payout from the pool's own stored LP supply."),
    S("bridge_release_value_unbound_to_proof", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Bridge release verifies the message but never "
             "binds the payout value: a bridge release / "
             "mint function DOES verify a message hash / "
             "signature / proof (ecrecover / ECDSA.recover / "
             "verifySignature present) and then transfers / "
             "mints a caller- or message-supplied amount "
             "with NO lookup comparing that amount to a "
             "deposit / lock / burn record for the transfer "
             "id (no deposits[txId].amount read, no "
             "lockedAmounts read, no value-equality "
             "require), so a verified hash over a fake "
             "withdrawal still pays the full caller-chosen "
             "amount - the Verus-Ethereum bridge shape (May "
             "2026, ~$11.58M, repeated Jul 2026, ~$7.5M). "
             "require(amount == deposits[txId].amount) is "
             "the protected shape. The function must also be "
             "bridge-shaped (a release / unlock name, a "
             "transfer / message identifier parameter, or a "
             "bridge contract): a plain public mint that "
             "verifies an allowlist proof and charges the "
             "caller per token is a paid mint, not a bridge "
             "release.",
      fix="Bind every release amount to a stored record: "
          "require(amount == deposits[txId].amount) (or the "
          "locked / burned record for the transfer id) "
          "after verifying the message, and mark the "
          "transfer consumed so it cannot pay twice."),
    S("merkle_proof_unbounded_leaf_index", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Merkle proof accepts an out-of-bounds leaf "
             "index: a proof-verification function taking a "
             "leaf index (and proof) verifies the proof "
             "(MerkleProof.verify / verifyCalldata / "
             "processProof) but NEVER checks the index "
             "against the tree / leaf count (no require"
             "(index < leafCount / treeSize / totalLeaves), "
             "no bounds check on the index anywhere on the "
             "path), so an out-of-bounds leaf verifies as "
             "valid and confers the privileges of a real "
             "leaf - the Hyperbridge shape (Apr 2026, "
             "~$2.5M). require(index < leafCount) is the "
             "protected shape.",
      fix="Bound the leaf index before verifying the proof: "
          "require(index < leafCount) (or treeSize / "
          "totalLeaves) at the top of every proof-"
          "verification function that takes a leaf index."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19)
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
            f"stranger can trigger this but receives nothing - "
            f"classified TRIGGER-ONLY under the receive rule.")
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


_IDENTITY_GATE_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses. The signature check and the
    _msgSender() gate under analysis are NOT gates here.
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


def _skip_fn(fn: Dict[str, Any], scope) -> bool:
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    return _caller_gated(fn, scope)


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


def _fn_body(text: str) -> str:
    """The function body (after the first `{`), for searches
    that must not match the signature's own parameter names."""
    i = text.find("{")
    return text[i + 1:] if i >= 0 else text


def _called_internal_texts(fn_text: str, scope) -> str:
    """Text of internal functions this function calls.

    A claimed-marker write, a collateral check, or a refund
    leg may live in a small internal helper (_markClaimed,
    _checkCollateral, _refundPreviousBidder) rather than in
    the entry point itself. A bare `foo(` call whose name
    matches a function defined in this contract is treated
    as an internal call; external calls (obj.foo(), token
    .transfer) and builtins (require, keccak256) never match
    a defined function name, so they are excluded.
    """
    defined = {f["name"]: f["text"] for f in scope.functions}
    out: List[str] = []
    for m in re.finditer(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                         fn_text):
        name = m.group(1)
        if name in defined and defined[name] not in out:
            out.append(defined[name])
    return "\n".join(out)


def _acts_after(text: str, pos: int, state: set) -> bool:
    """A state write or external call after `pos` in the function."""
    for p, _v in cl._state_writes(text, state):
        if p > pos:
            return True
    for c in cl._external_calls(text):
        if c["pos"] > pos:
            return True
    return False


_VALUE_MOVE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*transferFrom\s*\(|"
    r"safeTransfer\s*\(|safeTransferFrom\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\.\s*send\s*\(|\.\s*transfer\s*\{\s*value")


def _moves_value(text: str) -> bool:
    """A token / ETH payout of some kind in the function."""
    return bool(_VALUE_MOVE_RE.search(text))


# ---------------------------------------------------------------------------
# Sell-hook / escape-hatch / LP-mint / bridge-value / leaf-index patterns
# ---------------------------------------------------------------------------

# A Merkle proof verification call (OZ MerkleProof library).
_MERKLE_VERIFY_RE = re.compile(
    r"MerkleProof\s*\.\s*(?:verify|verifyCalldata|processProof)"
    r"\s*\(")


# ---------------------------------------------------------------------------
# 1. token_sell_hook_burns_pair_reserves_sync
# ---------------------------------------------------------------------------

_TRANSFER_HOOK_NAME_RE = re.compile(r"transfer|sell|hook|_update",
                                     re.I)
_PAIR_NAME_RE = re.compile(r"pair|pool", re.I)


def _pair_burn_pos(text: str) -> Optional[int]:
    """Position of a burn that debits a pair / pool address, else None.

    A burn from msg.sender or from an arbitrary account is not
    the shape - the burned tokens have to be the pair's own
    holdings (the first argument names a pair / pool).
    """
    for m in re.finditer(
            r"\b_?burn(?:From)?\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)",
            text):
        if _PAIR_NAME_RE.search(m.group(1)):
            return m.start()
    for m in re.finditer(
            r"\b_?balances?\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)"
            r"[^]]*\]\s*-=", text):
        if _PAIR_NAME_RE.search(m.group(1)):
            return m.start()
    return None


def _pair_sync_pos(text: str) -> Optional[int]:
    """Position of a pair reserve sync call, else None.

    pair.sync() / pool.sync(), or IUniswapV2Pair(...).sync().
    A bare .sync() on an unrelated receiver does not count.
    """
    for m in re.finditer(r"\.\s*sync\s*\(", text):
        head = text[:m.start()]
        rm = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", head)
        if rm and _PAIR_NAME_RE.search(rm.group(1)):
            return m.start()
        if "IUniswapV2Pair" in head[-60:]:
            return m.start()
    return None


def _pair_abuse_pos(fn_text: str, scope, fn_name: str
                    ) -> Optional[int]:
    """Earliest pair burn / sync in the function, or earliest
    call to an internal helper that burns pair tokens / syncs
    the pair. The hook may delegate the abuse to a helper
    (_sellHook / _burnPairReserves); the call site is where the
    abuse happens on the transfer path. The function's own
    signature is not a call - the name in `function _transfer(`
    must not count as a helper call to itself."""
    best: Optional[int] = None
    for pos in (_pair_burn_pos(fn_text), _pair_sync_pos(fn_text)):
        if pos is not None:
            best = pos if best is None else min(best, pos)
    defined = {f["name"]: f["text"] for f in scope.functions}
    for m in re.finditer(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                         fn_text):
        name = m.group(1)
        if name == fn_name:
            continue
        if fn_text[max(0, m.start() - 9):m.start()] == \
                "function ":
            continue
        if name in defined:
            helper = defined[name]
            if _pair_burn_pos(helper) is not None or \
                    _pair_sync_pos(helper) is not None:
                best = m.start() if best is None \
                    else min(best, m.start())
    return best


def _settle_recipient(fn_text: str, params: List[str],
                      state: set) -> Optional[Tuple[str, str]]:
    """Recipient of a transfer that settles by ledger credit.

    The shared classifier only reads a balance credit as a
    destination for mint-named functions, so a plain _transfer
    that credits balances[to] classifies UNRESOLVED there. The
    credit key IS the destination here: a caller parameter is
    CALLER-SUPPLIED, a stored address is FIXED, msg.sender is
    CALLER."""
    for m in re.finditer(
            r"\b_?balances?\s*\[\s*([A-Za-z_][A-Za-z0-9_.\[\]]*)"
            r"\s*\]\s*(?:\+=|=(?!=))", fn_text):
        key = m.group(1).split("[")[0].split(".")[0]
        if key in params:
            return ("CALLER-SUPPLIED",
                    f"transfer settles by crediting the caller "
                    f"parameter '{key}'")
        if key == "msg":
            return ("CALLER",
                    "transfer settles by crediting msg.sender")
        if key in state:
            return ("FIXED",
                    f"transfer settles by crediting the stored "
                    f"address '{key}'")
    return None


_SETTLE_RES = (
    # The transfer's own token movement: an external token
    # transfer, or the balance credit that settles the transfer
    # (to any destination - a credit to a fixed treasury settles
    # it just as a credit to `to` does).
    re.compile(r"\.\s*(?:safeTransfer|transfer|transferFrom)"
               r"\s*\("),
    re.compile(r"\b_?balances?\s*\[[^\]]+\]\s*(?:\+=|=(?!=))"),
)


def _settle_pos(text: str) -> Optional[int]:
    positions = [m.start() for p in _SETTLE_RES
                 for m in p.finditer(text)]
    return min(positions) if positions else None


def _analyze_sell_hook(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _TRANSFER_HOOK_NAME_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        abuse = _pair_abuse_pos(text, scope, fn["name"])
        if abuse is None:
            continue
        settle = _settle_pos(text)
        if settle is None or abuse >= settle:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' burns tokens held by "
            f"an AMM pair and/or syncs the pair's reserves "
            f"before the transfer's own token movement "
            f"completes (the pair burn / sync sits ahead of "
            f"the balance credit / token transfer that "
            f"settles the transfer), so the pool reprices "
            f"against the seller's remaining tokens and the "
            f"subsequent swap drains the pair. Gate "
            f"analysis: no caller-identity gate, pair-reserve "
            f"abuse mid-transfer.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated transfer hook: pair reserves "
                    "burned / synced before the transfer "
                    "settles")
        recipient, rdetail = cl.classify_recipient(text)
        if recipient == "UNRESOLVED":
            settled = _settle_recipient(text, _fn_params(fn),
                                        state)
            if settled is not None:
                recipient, rdetail = settled
        out.append(_classify(item, recipient, rdetail))
    return out


# ---------------------------------------------------------------------------
# 2. escape_hatch_unbound_public_inputs
# ---------------------------------------------------------------------------

_ESCAPE_NAME_RE = re.compile(r"escape|emergencyWithdraw", re.I)
_PROOF_PARAM_RE = re.compile(
    r"proofId|publicOutputs?|publicInputs?|numRealTxs|"
    r"proofOutput", re.I)

# A real proof binding on the escape path: a proof verifier
# call, or a require / comparison that binds the payout to a
# committed state root / committed output / numRealTxs count.
# A bare state-root state variable that is never checked is
# NOT a binding - the check has to compare or require.
_PROOF_VERIFY_RES = (
    re.compile(r"\bverifyProof\s*\("),
    re.compile(r"\bverifyPublicInputs\s*\("),
    re.compile(r"\bcheckProof\s*\("),
    re.compile(r"\b_verifyProof\s*\("),
    re.compile(r"MerkleProof\s*\.\s*(?:verify|verifyCalldata|"
               r"processProof)\s*\("),
    re.compile(r"\bverify\s*\(\s*[^)]*proof", re.I),
    re.compile(r"require\s*\([^)]*\bstateRoot\b"),
    re.compile(r"\bstateRoot\s*(?:==|!=)"),
    re.compile(r"require\s*\([^)]*\bcommittedRoot\b"),
    re.compile(r"\bcommittedRoot\s*(?:==|!=)"),
    re.compile(r"require\s*\([^)]*\bcommittedOutput\w*\b"),
    re.compile(r"\bcommittedOutput\w*\s*(?:==|!=)"),
    re.compile(r"require\s*\([^)]*numRealTxs[^)]*(?:==|>=|<=)"),
)


def _escape_sized_by_params(fn_text: str, params: List[str]
                            ) -> Optional[str]:
    """A proof / output parameter that sizes the payout, else None.

    The parameter has to feed the payout: decoded from the
    public output, assigned into an amount local, or passed
    straight into a transfer call. A parameter that is merely
    declared (or only logged) does not size anything.
    """
    body = _fn_body(fn_text)
    proof_params = [p for p in params
                    if _PROOF_PARAM_RE.search(p)]
    for p in proof_params:
        if re.search(r"abi\.decode\s*\(\s*" + re.escape(p) +
                     r"\b", body):
            return p
        if re.search(r"\bamount\w*\s*=[^;]{0,120}\b" +
                     re.escape(p) + r"\b", body):
            return p
        for m in re.finditer(
                r"\.\s*(?:transfer|transferFrom|safeTransfer|"
                r"safeTransferFrom)\s*\(", body):
            i = body.index("(", m.start())
            inner, _ = _balanced(body, i)
            if re.search(r"\b" + re.escape(p) + r"\b", inner):
                return p
    return None


def _analyze_escape_hatch(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _ESCAPE_NAME_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _moves_value(text):
            continue
        sized = _escape_sized_by_params(text, _fn_params(fn))
        if sized is None:
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if any(p.search(searched) for p in _PROOF_VERIFY_RES):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' transfers value sized "
            f"by the caller-supplied proof / output parameter "
            f"'{sized}' with no proof verification anywhere "
            f"on the path (no verifyProof / Merkle check / "
            f"state-root binding / numRealTxs consistency "
            f"check, not even in an internal helper it calls), "
            f"so the caller chooses the public inputs and "
            f"therefore the payout. Gate analysis: no "
            f"caller-identity gate, no proof binding on the "
            f"path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated escape hatch: payout sized by "
                    "unverified caller-supplied public inputs")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. lp_mint_unverified_caller_supplied
# ---------------------------------------------------------------------------

_LP_FN_RE = re.compile(
    r"removeLiquidity|withdrawLiquidity|exitPool", re.I)
_LP_PARAM_RE = re.compile(
    r"^(?:lpToken|lpMint|lp|shareToken|poolToken|"
    r"liquidityToken)$", re.I)


def _lp_supply_sized(body: str, param: str) -> bool:
    """totalSupply() / balanceOf() whose receiver expression
    names the caller-supplied LP token parameter."""
    for m in re.finditer(r"\.(?:totalSupply|balanceOf)\s*\(",
                         body):
        start = max(body.rfind(";", 0, m.start()),
                    body.rfind("{", 0, m.start()),
                    body.rfind("=", 0, m.start()))
        recv = body[start + 1:m.start()]
        if re.search(r"\b" + re.escape(param) + r"\b", recv):
            return True
    return False


def _lp_bound(text: str, param: str, state: set) -> bool:
    """The LP parameter is bound to the pool's own LP token:
    compared against a stored value, or the payout is sized
    from a stored token instead of the parameter. A zero-address
    check (lpToken != address(0)) is NOT a binding."""
    for m in re.finditer(r"\b" + re.escape(param) +
                         r"\s*(?:==|!=)\s*"
                         r"([A-Za-z_][A-Za-z0-9_]*)", text):
        if m.group(1) in state:
            return True
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)"
                         r"\s*(?:==|!=)\s*" +
                         re.escape(param) + r"\b", text):
        if m.group(1) in state:
            return True
    for m in re.finditer(r"\.(?:totalSupply|balanceOf)\s*\(",
                         text):
        start = max(text.rfind(";", 0, m.start()),
                    text.rfind("{", 0, m.start()),
                    text.rfind("=", 0, m.start()))
        recv = text[start + 1:m.start()]
        for var in state:
            if var != param and re.search(
                    r"\b" + re.escape(var) + r"\b", recv):
                return True
    return False


def _analyze_lp_mint(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _LP_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        lp_params = [p for p in params
                     if _LP_PARAM_RE.match(p)]
        if not lp_params:
            continue
        body = _fn_body(text)
        sized = [p for p in lp_params
                 if _lp_supply_sized(body, p)]
        if not sized:
            continue
        if not _moves_value(text):
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if _lp_bound(searched, sized[0], state):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' takes the LP / share "
            f"token as the caller parameter '{sized[0]}' and "
            f"sizes the payout from THAT token's supply / "
            f"balance, with no check binding the parameter to "
            f"the pool's own LP token (no require against a "
            f"stored LP token, no payout sized from pool "
            f"storage, not even in an internal helper it "
            f"calls), so a forged mint with supply 1 passes "
            f"the proportion checks and withdraws ~100% of "
            f"the reserves. Gate analysis: no "
            f"caller-identity gate, no LP-mint binding on the "
            f"path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated liquidity removal: payout sized "
                    "from a caller-supplied LP mint")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. bridge_release_value_unbound_to_proof
# ---------------------------------------------------------------------------

_RELEASE_NAME_RE = re.compile(
    r"release|unlock|executeTransfer|processTransfer|mint",
    re.I)

# The function has to be bridge-shaped: a release / unlock /
# transfer-execution name, a transfer / message identifier
# parameter (txId / messageId / nonce / ...), or a bridge
# contract. A bare `mint` name alone is not enough: a public
# NFT mint that verifies an allowlist Merkle proof and charges
# the caller per token (ERC20Plus mintManyERC20AL, found
# 2026-11-17 live run) verifies a proof and mints a
# caller-chosen amount, but it is a paid mint against caps, not
# a bridge release of locked funds.
_BRIDGE_NAME_RE = re.compile(
    r"release|unlock|executeTransfer|processTransfer", re.I)
_BRIDGE_ID_PARAM_RE = re.compile(
    r"txId|transferId|messageId|depositId|nonce|messageHash|"
    r"digest|proofId|transferHash", re.I)


def _bridge_shaped(fn_name: str, params: List[str],
                   contract_name: str) -> bool:
    if _BRIDGE_NAME_RE.search(fn_name):
        return True
    if any(_BRIDGE_ID_PARAM_RE.search(p) for p in params):
        return True
    return "bridge" in (contract_name or "").lower()


# Verification PRESENT on the release path: a signature /
# proof check. (No verification at all is the
# bridge_message_payload_injection shape, not this one.)
_VERIFY_MSG_RES = (
    re.compile(r"\becrecover\s*\("),
    re.compile(r"ECDSA\s*\.\s*recover\s*\("),
    re.compile(r"\bverifySignature\s*\("),
    re.compile(r"SignatureChecker\s*\.\s*isValidSignature"),
    re.compile(r"MerkleProof\s*\.\s*(?:verify|verifyCalldata|"
               r"processProof)\s*\("),
    re.compile(r"\bverify\s*\(\s*[^)]*(?:hash|proof|signature)",
               re.I),
)

# A stored deposit / lock / burn record read - the amount
# being compared against a record for the transfer id.
_RECORD_READ_RES = (
    re.compile(r"\bdeposits\s*\["),
    re.compile(r"\blockedAmounts\s*\["),
    re.compile(r"\blockedBalances\s*\["),
    re.compile(r"\bburnedAmounts\s*\["),
    re.compile(r"\blocks\s*\["),
    re.compile(r"\bescrowed\s*\["),
    re.compile(r"\bclaimedAmounts\s*\["),
)
_VALUE_BIND_RE = re.compile(
    r"require\s*\([^)]*\bamount\w*\s*==[^)]*\.\s*amount\b")


def _release_amount_used(body: str, amount_params: List[str]
                         ) -> Optional[str]:
    """An amount parameter passed into a payout call, else None."""
    for p in amount_params:
        for m in re.finditer(
                r"\.\s*(?:transfer|transferFrom|safeTransfer|"
                r"safeTransferFrom)\s*\(", body):
            i = body.index("(", m.start())
            inner, _ = _balanced(body, i)
            if re.search(r"\b" + re.escape(p) + r"\b", inner):
                return p
        if re.search(r"\b_mint\s*\(\s*[^;]{0,80}\b" +
                     re.escape(p) + r"\b", body):
            return p
    return None


def _analyze_bridge_value(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _RELEASE_NAME_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        if not _bridge_shaped(fn["name"], params, contract_name):
            continue
        amount_params = [p for p in params
                         if re.search(r"amount|value|payout",
                                      p, re.I)]
        if not amount_params:
            continue
        body = _fn_body(text)
        used = _release_amount_used(body, amount_params)
        if used is None:
            continue
        if not _moves_value(text):
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if not any(p.search(searched) for p in _VERIFY_MSG_RES):
            continue
        if any(p.search(searched) for p in _RECORD_READ_RES):
            continue
        if _VALUE_BIND_RE.search(searched):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies the message "
            f"(ecrecover / signature check present) and then "
            f"pays the caller-supplied amount '{used}' with no "
            f"lookup comparing that amount to a deposit / "
            f"lock / burn record for the transfer id (no "
            f"deposits[txId].amount read, no lockedAmounts "
            f"read, no value-equality require, not even in an "
            f"internal helper it calls), so a verified hash "
            f"over a fake withdrawal still pays the full "
            f"caller-chosen amount. Gate analysis: no "
            f"caller-identity gate, verification present but "
            f"the value unbound to any stored record.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "verified bridge release: message checked, "
                    "payout amount never compared to a stored "
                    "lock / burn record")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. merkle_proof_unbounded_leaf_index
# ---------------------------------------------------------------------------

_VERIFY_FN_RE = re.compile(r"verif", re.I)
_INDEX_PARAM_RE = re.compile(
    r"^(?:index|leafIndex|leafIdx|idx|leafPosition|"
    r"position)$", re.I)
_LEAF_PROOF_PARAM_RE = re.compile(r"proof", re.I)
_COUNT_WORD_RE = re.compile(
    r"leafCount|treeSize|totalLeaves|numLeaves|leafTotal|"
    r"maxIndex|count|size|length|depth", re.I)


def _index_bound(text: str, idx: str) -> bool:
    """A require / if / assert that compares the leaf index
    against a tree / leaf count. The comparison has to mention
    the index, a comparison operator, and a count-ish term in
    the same statement - a bare `index < 100` literal bound is
    not a tree binding."""
    for m in re.finditer(
            r"(?:require|if|assert)\s*\(([^;]{0,200})\)", text):
        stmt = m.group(1)
        if not re.search(r"\b" + re.escape(idx) + r"\b", stmt):
            continue
        if not re.search(r"<|<=|>=|>", stmt):
            continue
        if _COUNT_WORD_RE.search(stmt):
            return True
    return False


def _analyze_merkle_index(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _VERIFY_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        idx_params = [p for p in params
                      if _INDEX_PARAM_RE.match(p)]
        if not idx_params:
            continue
        if not any(_LEAF_PROOF_PARAM_RE.search(p) for p in params):
            continue
        if not _MERKLE_VERIFY_RE.search(text):
            continue
        # The verification has to gate something: a value move
        # or a state write. A pure view verifier that returns
        # a bool confers nothing by itself.
        if not (_moves_value(text) or
                list(cl._state_writes(text, state))):
            continue
        searched = text + "\n" + _called_internal_texts(text, scope)
        if _index_bound(searched, idx_params[0]):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a Merkle "
            f"proof for leaf index '{idx_params[0]}' but never "
            f"checks that index against the tree / leaf count "
            f"(no require(index < leafCount / treeSize / "
            f"totalLeaves), no bounds check on the index "
            f"anywhere on the path, not even in an internal "
            f"helper it calls), so an out-of-bounds leaf "
            f"verifies as valid and confers the privileges of "
            f"a real leaf. Gate analysis: no caller-identity "
            f"gate, no leaf-index bound on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated proof verification: leaf index "
                    "never bound-checked against the tree")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "token_sell_hook_burns_pair_reserves_sync": _analyze_sell_hook,
    "escape_hatch_unbound_public_inputs": _analyze_escape_hatch,
    "lp_mint_unverified_caller_supplied": _analyze_lp_mint,
    "bridge_release_value_unbound_to_proof": _analyze_bridge_value,
    "merkle_proof_unbounded_leaf_index": _analyze_merkle_index,
}


def analyze_deep24_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-20 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep24_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit24Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 24)"
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
        for item in analyze_deep24_source(
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
                source="deep audit detector batch 24 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit24Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 24) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
