"""Deep-audit detectors, batch 13: AI plugin dev (2026-11-09).

Five more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-12 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- residual_balance_sweep_ungated: a public / external function
  that sends the contract's ENTIRE native balance
  (address(this).balance) or its entire token balance
  (token.balanceOf(address(this))) to msg.sender or a
  caller-supplied recipient, with no caller-identity gate and
  no per-user ledger bounding the payout. The Dex223 SwapRouter
  shape (issue #77, 2026-11-07): public refundETH() /
  unwrapWETH9() let any caller claim ETH / WETH9 stuck in the
  router. A payout sized by the caller's own recorded balance
  (a per-user refund) or by an amount parameter stays silent.
  Distinct from built aa_execute_ungated (account execute
  forwards a caller-supplied call) and from the generic
  ungated-function family (this one proves the payout is the
  contract's full residual balance).
- pyth_price_unsafe_unchecked: a function consumes Pyth
  getPriceUnsafe() output for a valuation / liquidation /
  health decision with NEITHER a publishTime recency check
  NOR a conf-width check in the consuming function (and no
  getPriceNoOlderThan). The ZeroLend Immunefi #29068 shape
  (2024-03) and the Euler PythOracle audit pattern: the safe
  shape is getPriceNoOlderThan + conf vs maxConfWidth.
  Distinct from built system_stale_oracle_data (Chainlink
  latestRoundData only) and cp_proto_single_source_oracle
  (DEX reserves, not a price-feed consumer).
- paymaster_sponsorship_unbounded: validatePaymasterUserOp
  returns success (validationData 0) with no per-user / per-op
  cap, no allowlist / token whitelist, and no signature /
  ecrecover check, so any UserOp gets sponsored and the
  paymaster is drained via high-verificationGasLimit ops.
  A signature check, a cap, or an allowlist suppresses it
  (off-chain signer paymasters are the legitimate pattern).
  Distinct from built aa_validation_ungated (validateUserOp
  only) - this is the paymaster half of the AA surface.
- approval_binds_id_not_version: an approve / authorize
  function takes ONLY an id (incident / proposal / assessment
  id) with no version / round / payload-hash parameter, while
  execution resolves the CURRENT round / version at run time
  and a cancel + resubmit path can swap the payload under a
  pending approval. The Firelight Immunefi #88618 / #88366
  shape (Aug 2026, High): a 100-unit reviewed schedule swapped
  for 1,000 units. Distinct from built
  eip712_digest_unbound_to_payload (signature digest, not
  on-chain approval resolution) and from ERC-20 approve
  (two parameters, no version resolution).
- stale_permission_after_replacement: a privileged role /
  allowance is granted to a contract address held in a mutable
  state variable, and the setter that replaces the address
  never revokes the old address's role / allowance, so the
  legacy contract keeps draining rights. The Troves shape
  (2026-10-31, ~$667k, ~8.6 BTC from the xWBTC / WBTC vault).
  A setter that revokes the old address first stays silent;
  an address that was never granted anything stays silent.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. (Same narrowing
of cl._gated_deep as batch 12.) The stale-permission detector
is the exception: the risk is the stale grant, not the
setter's gate, so it reads the setter regardless of gate and
says so in the gate analysis. The approval detector is the
same: the threat is a privileged swapper, not an ungated
caller. The Pyth detector does not skip view functions:
price readers are commonly view, and _price_consumed is the
real gate (a function that merely returns the price stays
silent).

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
FAMILY = "deep13"

SPECS = [
    S("residual_balance_sweep_ungated", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Ungated residual-balance sweep: a public / external "
             "function sends the contract's entire native balance "
             "(address(this).balance) or its entire token balance "
             "(token.balanceOf(address(this))) to msg.sender or a "
             "caller-supplied recipient, with no caller-identity "
             "gate and no per-user ledger bounding the payout - "
             "the Dex223 SwapRouter refundETH / unwrapWETH9 shape. "
             "A payout sized by the caller's own recorded balance "
             "or by an amount parameter is the protected shape.",
      fix="Gate residual sweeps behind onlyOwner / a role, or "
          "size every payout from the caller's own recorded "
          "balance (never from the contract's full balance), and "
          "sweep leftovers to a fixed treasury, never to "
          "msg.sender or a caller-supplied address."),
    S("pyth_price_unsafe_unchecked", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Pyth getPriceUnsafe consumed unchecked: a function "
             "reads a Pyth price via getPriceUnsafe() and uses it "
             "for a valuation / liquidation / health decision with "
             "NEITHER a publishTime recency check NOR a conf-width "
             "check in the consuming function (and no "
             "getPriceNoOlderThan) - the ZeroLend Immunefi #29068 "
             "shape. The protected shape is getPriceNoOlderThan "
             "plus a conf check against a maximum width.",
      fix="Use getPriceNoOlderThan(id, maxAge) and reject prices "
          "whose conf exceeds a maximum width before using the "
          "price in any valuation, liquidation, or health "
          "check."),
    S("paymaster_sponsorship_unbounded", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Paymaster sponsorship unbounded: "
             "validatePaymasterUserOp returns success "
             "(validationData 0) with no per-user / per-op cap, "
             "no allowlist / token whitelist, and no signature / "
             "ecrecover check, so any UserOp gets sponsored and "
             "the paymaster is drained via high-gas ops. A "
             "signature check, a spending cap, or an allowlist is "
             "the protected shape (off-chain signer paymasters "
             "are the legitimate pattern).",
      fix="Bind sponsorship to a verified payer (signature / "
          "ecrecover), a per-user spending cap, and an allowlist "
          "or token whitelist before returning validationData 0."),
    S("approval_binds_id_not_version", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Approval binds an id, not the version reviewed: an "
             "approve / authorize function takes ONLY an id "
             "(incident / proposal / assessment id) with no "
             "version / round / payload-hash parameter, while "
             "execution resolves the CURRENT round / version at "
             "run time and a cancel + resubmit path can swap the "
             "payload under a pending approval - the Firelight "
             "Immunefi #88618 / #88366 shape. Binding the "
             "approval to a version and a payload hash is the "
             "protected shape.",
      fix="Approve (id, version, payloadHash) and require the "
          "execution to match the exact version and hash that "
          "was reviewed; never resolve the current round at "
          "execution time under an id-only approval."),
    S("stale_permission_after_replacement", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Stale permission after replacement: a privileged "
             "role / allowance is granted to a contract address "
             "held in a mutable state variable, and the setter "
             "that replaces the address never revokes the old "
             "address's role / allowance, so the legacy contract "
             "keeps draining rights - the Troves shape "
             "(2026-10-31, ~$667k). A setter that revokes the old "
             "address first is the protected shape.",
      fix="In the setter, revoke the old address's role / "
          "allowance BEFORE assigning the new address, then "
          "grant to the new address in the same step."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12)
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
    r"_msgSender\s*\(\s*\)\s*(==|!=)|"
    r"(==|!=)\s*_msgSender\s*\(\s*\)|"
    r"hasRole\s*\(|has[A-Z][A-Za-z0-9_]*Role\s*\(|"
    r"_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(
    r"\bonly[A-Z][A-Za-z0-9_]*\b|\bonly\s*\(")
# Bare allowlist-mapping read as the whole require condition,
# e.g. require(isTxLimitExempt[msg.sender]): an allowlist gate,
# not a balance check (no comparison operator after the read).
_ALLOWLIST_GATE_RE = re.compile(
    r"require\s*\(\s*!?\s*[A-Za-z_][A-Za-z0-9_]*\s*\[\s*"
    r"(?:msg\.sender|_msgSender\s*\(\s*\))\s*\]\s*"
    r"(?:==\s*true|!=\s*false)?\s*\)")


def _modifier_override_gated(scope, tok: str) -> bool:
    """A modifier may be declared abstract (virtual, no body)
    AND overridden with a gate body elsewhere in the source
    (e.g. Withdrawable's protectedWithdrawal overridden with
    _checkRole(DEFAULT_ADMIN_ROLE)). The scope's modifier dict
    can hold the body-less declaration, so scan the scoped
    text for every declaration of the modifier and check each
    body for a gate."""
    for m in re.finditer(
            rf"modifier\s+{re.escape(tok)}\s*\([^)]*\)[^{{;]*\{{",
            scope.scoped_text):
        close = scope.scoped_text.find("}", m.end())
        if close < 0 or close - m.end() > 400:
            continue
        body = scope.scoped_text[m.end():close]
        if (_IDENTITY_GATE_RE.search(body) or
                _ONLY_MOD_RE.search(body)):
            return True
    return False


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses.
    """
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or _IDENTITY_GATE_RE.search(text):
        return True
    if _ALLOWLIST_GATE_RE.search(text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and (("msg.sender" in body or
                         "_msgSender" in body) and
                         ("==" in body or "!=" in body)):
                return True
            if _modifier_override_gated(scope, tok):
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


def _call_args(text: str, call_match) -> List[str]:
    paren = text.index("(", call_match.start())
    inner, _ = _balanced(text, paren)
    return _split_top(inner)


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


def _fn_addr_params(fn: Dict[str, Any]) -> List[str]:
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        if "address" in part:
            toks = [t for t in part.split()
                    if t not in ("calldata", "memory", "storage",
                                 "payable")]
            if len(toks) >= 2:
                out.append(toks[-1])
    return out

# ---------------------------------------------------------------------------
# 1. Ungated residual-balance sweep (Dex223 refundETH / unwrapWETH9)
# ---------------------------------------------------------------------------

_NATIVE_FULL_RE = re.compile(
    r"\.call\s*\{\s*value\s*:\s*address\s*\(\s*this\s*\)\s*"
    r"\.\s*balance\s*\}|"
    r"\.(?:transfer|send)\s*\(\s*address\s*\(\s*this\s*\)\s*"
    r"\.\s*balance\s*\)")
_TOKEN_FULL_RE = re.compile(
    r"\.(?:transfer|safeTransfer)\s*\([^;]{0,160}?"
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"\.transferFrom\s*\([^;]{0,160}?"
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
_WETH_FULL_RE = re.compile(
    r"\.withdraw\s*\(\s*\S+\s*\.?\s*balanceOf\s*\(\s*address\s*"
    r"\(\s*this\s*\)\s*\)\s*\)")


def _analyze_residual_sweep(src, spec, compiler,
                            contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        m = (_NATIVE_FULL_RE.search(text) or
             _TOKEN_FULL_RE.search(text) or
             _WETH_FULL_RE.search(text))
        if not m:
            continue
        # The payout must be the contract's full balance, not a
        # per-user ledger amount: the regexes above already
        # require address(this).balance / balanceOf(address
        # (this)) as the transferred amount, so a payout sized
        # from deposits[msg.sender] or an amount parameter can
        # never match. A WETH unwrap of the full balance only
        # counts when the unwrapped ETH then leaves to a
        # caller-controlled destination in the same function.
        if _WETH_FULL_RE.search(text) and not (
                _NATIVE_FULL_RE.search(text)):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' moves the contract's "
            f"full residual balance ('{m.group(0)[:80]}') with "
            f"no caller-identity gate, so any stranger can claim "
            f"whatever balance is sitting in the contract. Gate "
            f"analysis: no only* modifier, no msg.sender "
            f"identity check, no role check on the sweep path; "
            f"the payout is the contract's full balance, not a "
            f"per-user recorded amount.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated residual sweep: full contract "
                    "balance to a caller-controlled destination, "
                    "no owner / role gate")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. Pyth getPriceUnsafe consumed unchecked (ZeroLend #29068)
# ---------------------------------------------------------------------------

_UNSAFE_CALL_RE = re.compile(r"getPriceUnsafe\s*\(")
_SAFE_CALL_RE = re.compile(r"getPriceNoOlderThan\s*\(")
_PRICE_DIRECT_RE = re.compile(
    r"\.price\s*(\*|/|\+|-|>|<|>=|<=|==|!=)|"
    r"require\s*\([^)]*\.price|"
    r"if\s*\([^)]*\.price")
_PRICE_ASSIGN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]{0,80}?\.price\b")


def _price_consumed(text: str) -> bool:
    """The unsafe price flows into a valuation: used directly
    in arithmetic / a comparison, or assigned to a local that
    is then used in arithmetic / a comparison / a require."""
    if _PRICE_DIRECT_RE.search(text):
        return True
    m = _PRICE_ASSIGN_RE.search(text)
    if not m:
        return False
    var = m.group(1)
    if re.search(rf"\b{var}\b\s*(\*|/|\+|-|>|<|>=|<=|==|!=)",
                 text):
        return True
    if re.search(rf"(\*|/|\+|-|>|<|>=|<=|==|!=)\s*[^;]{{0,40}}?"
                 rf"\b{var}\b", text):
        return True
    if re.search(rf"require\s*\([^)]*\b{var}\b", text):
        return True
    if re.search(rf"if\s*\([^)]*\b{var}\b", text):
        return True
    return False


_PUBLISH_GUARD_RE = re.compile(
    r"publishTime\s*(>=|<=|>|<|==|!=)|"
    r"block\.timestamp\s*-\s*\S{0,40}?publishTime|"
    r"publishTime\s*\+\s*\S{0,40}?\s*(<=|>=|<|>)|"
    r"\bmaxAge\b|\bstale\b", re.I)
_CONF_GUARD_RE = re.compile(
    r"\.conf\s*(<=|>=|<|>|==|!=)|"
    r"\bmaxConf\w*\b|\bconf\w*\s*(<=|>=|<|>)", re.I)


def _analyze_pyth_unsafe(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        # No _skip_fn here on purpose: price readers are
        # commonly view functions, and the risk is the
        # unchecked price feeding a valuation / liquidation
        # elsewhere. _price_consumed is the real gate: a
        # function that merely returns the price stays silent.
        text = fn["text"]
        if not _UNSAFE_CALL_RE.search(text):
            continue
        if _SAFE_CALL_RE.search(text):
            continue
        if not _price_consumed(text):
            continue
        # Either a publishTime recency check or a conf-width
        # check in the consuming function is enough to stay
        # silent: the finding is the NEITHER case.
        if (_PUBLISH_GUARD_RE.search(text) or
                _CONF_GUARD_RE.search(text)):
            continue
        m = _UNSAFE_CALL_RE.search(text)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' calls getPriceUnsafe "
            f"('{m.group(0)[:40]}') and uses the returned price "
            f"in a valuation, but the consuming function has no "
            f"publishTime recency check, no conf-width check, "
            f"and no getPriceNoOlderThan call, so an arbitrarily "
            f"stale or wide-confidence price is accepted. Gate "
            f"analysis: no oracle-freshness gate on the price "
            f"path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "unchecked Pyth price: getPriceUnsafe with "
                    "no publishTime / conf check in the consumer")
        out.append(_finish_recipient(spec, item, text))
    return out

# ---------------------------------------------------------------------------
# 3. Paymaster sponsorship unbounded (ERC-4337 paymaster half)
# ---------------------------------------------------------------------------

_PAYMASTER_FN_RE = re.compile(r"validatePaymasterUserOp")
_SIG_CHECK_RE = re.compile(
    r"ecrecover|ECDSA\s*\.\s*recover|SignatureChecker|"
    r"isValidSignature|verifySignature|_verifySig", re.I)
_CAP_RE = re.compile(
    r"\bspent\s*\[|\bsponsored\s*\[|\bmaxCost\b|"
    r"\bmaxSpend\b|\bmaxGas\b|"
    r"gasLimit\s*(<=|>=|<|>)|"
    r"require\s*\([^)]*<=?\s*max\w*", re.I)
_ALLOW_RE = re.compile(
    r"allowlist|whitelist|isAllowed|supportedToken|"
    r"allowedToken|allowedPaymaster", re.I)
_SUCCESS_RE = re.compile(
    r"return\s*\([^)]*,\s*0\s*\)|"
    r"validationData\s*=\s*0\b")


def _analyze_paymaster_unbounded(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _PAYMASTER_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        # Body only: a `maxCost` parameter NAME in the signature
        # is not a cap, and a signature mentioning a verifier is
        # not a check.
        body = text.split("{", 1)[1] if "{" in text else text
        if not _SUCCESS_RE.search(body):
            continue
        if _SIG_CHECK_RE.search(body):
            continue
        if _CAP_RE.search(body):
            continue
        if _ALLOW_RE.search(body):
            continue
        m = _SUCCESS_RE.search(body)
        detail = spec.detail + (
            f" Observed: '{fn['name']}' returns success "
            f"('{m.group(0)[:50]}') with no signature check, no "
            f"per-user / per-op spending cap, and no allowlist / "
            f"token whitelist in the function, so any UserOp is "
            f"sponsored and the paymaster can be drained via "
            f"high-verificationGasLimit ops. Gate analysis: no "
            f"payer verification and no sponsorship bound on the "
            f"paymaster path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "unbounded paymaster: validatePaymasterUserOp "
                    "accepts all with no signature, cap, or "
                    "allowlist")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. Approval binds an id, not the version reviewed (Firelight)
# ---------------------------------------------------------------------------

_APPROVE_FN_RE = re.compile(r"approve|authorize|confirm", re.I)
_ID_PARAM_RE = re.compile(
    r"^(incident|proposal|assessment|claim|request)?[Ii]d$")
_VERSION_PARAM_RE = re.compile(
    r"round|version|payloadHash|assessmentHash|scheduleHash",
    re.I)
_CURRENT_RE = re.compile(
    r"currentRound|currentVersion|latestRound|"
    r"currentAssessment|currentSchedule", re.I)
_CANCEL_FN_RE = re.compile(r"^cancel", re.I)
_RESUBMIT_FN_RE = re.compile(
    r"^(submit|create|propose|resubmit)", re.I)


def _analyze_approval_id_only(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    names = [fn["name"] for fn in fns]
    has_cancel = any(_CANCEL_FN_RE.search(n) for n in names)
    has_resubmit = any(_RESUBMIT_FN_RE.search(n) for n in names)
    if not (has_cancel and has_resubmit):
        return []
    # Execution resolves the current round / version at run
    # time somewhere in the contract.
    if not _CURRENT_RE.search(scope.scoped_text):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _APPROVE_FN_RE.search(fn["name"]):
            continue
        # No _skip_fn here on purpose: the threat is not an
        # ungated stranger calling approve, it is a privileged
        # swapper (curator) replacing the payload under an
        # approval that reviewed a different version. The
        # approve function's own gate does not mitigate that.
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        params = _fn_params(fn)
        if len(params) != 1:
            continue
        if not _ID_PARAM_RE.match(params[0]):
            continue
        if _VERSION_PARAM_RE.search(fn["signature"]):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' approves by id only "
            f"('{params[0]}', no version / round / payload-hash "
            f"parameter) while the contract resolves the "
            f"current round at execution time and exposes a "
            f"cancel + resubmit path, so a replacement payload "
            f"can execute under an approval that reviewed a "
            f"different version. Gate analysis: the approval "
            f"does not bind the reviewed version; the cancel / "
            f"resubmit path can swap the payload underneath it.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "id-only approval: no version / hash bound, "
                    "current round resolved at execution, cancel "
                    "+ resubmit can swap the payload")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 5. Stale permission after replacement (Troves legacy role)
# ---------------------------------------------------------------------------

_STATE_ADDR_RE = re.compile(
    r"\baddress\s+(?:payable\s+)?(?:public\s+|internal\s+|"
    r"private\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*[^;]+)?;")
_REVOKE_RE_TMPL = (
    r"revokeRole\s*\([^,]+,\s*{var}\s*\)|"
    r"_revokeRole\s*\([^,]+,\s*{var}\s*\)|"
    r"approve\s*\(\s*{var}\s*,\s*0\s*\)|"
    r"revoke\s*\(\s*{var}\s*\)")


def _grant_sites(scoped_text: str, var: str) -> bool:
    """True when the state-var address is granted a role /
    allowance somewhere in the contract. Word boundaries
    matter: OZ's internal _approve(owner, ...) must not count
    as a grant to the variable."""
    pats = [
        rf"\bgrantRole\s*\([^,]+,\s*{var}\s*\)",
        rf"\b_grantRole\s*\([^,]+,\s*{var}\s*\)",
        rf"\bapprove\s*\(\s*{var}\s*,",
        rf"\bsetOperator\s*\(\s*{var}\s*\)",
        rf"\bgrantOperator\s*\(\s*{var}\s*\)",
    ]
    return any(re.search(p, scoped_text) for p in pats)


def _analyze_stale_permission(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state_vars = set(_STATE_ADDR_RE.findall(scoped))
    if not state_vars:
        return []
    # Only variables that actually hold a granted permission.
    granted = [v for v in state_vars if _grant_sites(scoped, v)]
    if not granted:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] == "constructor":
            # Initial setup, not a replacement: the constructor
            # granting to the first address is not a stale
            # permission.
            continue
        # Internal / private functions are not entry points: a
        # stranger cannot reach the setter except through a
        # public wrapper, which is the function to flag.
        if re.search(r"\b(internal|private)\b", fn["signature"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        params = set(_fn_params(fn))
        addr_params = set(_fn_addr_params(fn))
        for var in granted:
            # Setter: assigns the state var from a parameter.
            m = re.search(
                rf"\b{var}\s*=\s*([A-Za-z_][A-Za-z0-9_]*)",
                text)
            if not m:
                continue
            if m.group(1) not in params:
                continue
            if m.group(1) not in addr_params:
                continue
            # A one-time setter (reverts once the address is
            # already set) can never replace a live grant: the
            # stale-permission path is unreachable.
            one_time_re = re.compile(
                rf"if\s*\(\s*{re.escape(var)}\s*!=\s*address\s*"
                rf"\(\s*0\s*\)\s*\)\s*revert|"
                rf"require\s*\(\s*{re.escape(var)}\s*==\s*"
                rf"address\s*\(\s*0\s*\)")
            if one_time_re.search(text):
                continue
            # Revoking the old address first is the protected
            # shape. Note: the setter's own gate is NOT the
            # point here - the risk is the stale grant the old
            # address keeps after replacement.
            revoke_re = re.compile(
                _REVOKE_RE_TMPL.format(var=re.escape(var)))
            if revoke_re.search(text):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' replaces the "
                f"permissioned address '{var}' with a caller-"
                f"supplied address but never revokes the old "
                f"address's role / allowance, so the legacy "
                f"contract keeps its draining rights after "
                f"replacement. Gate analysis: the setter's own "
                f"gate is not the issue - the stale grant is; "
                f"no revokeRole / approve(old, 0) on the "
                f"replacement path.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "stale permission: setter replaces a "
                        "granted address without revoking the old "
                        "one's role / allowance")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


ANALYZERS = {
    "residual_balance_sweep_ungated": _analyze_residual_sweep,
    "pyth_price_unsafe_unchecked": _analyze_pyth_unsafe,
    "paymaster_sponsorship_unbounded":
        _analyze_paymaster_unbounded,
    "approval_binds_id_not_version": _analyze_approval_id_only,
    "stale_permission_after_replacement":
        _analyze_stale_permission,
}


def analyze_deep13_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-13 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)

# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 collection / fetch /
# proxy resolution; analysis is analyze_deep13_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit13Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 13)"
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
        for item in analyze_deep13_source(
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
                source="deep audit detector batch 13 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit13Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 13) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
