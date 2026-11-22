"""Deep-audit detectors, batch 31: Hamonis-taught patterns.

Four chain-agnostic EVM detectors built from the @hamonis.io
video series (36 videos, Nov 2-22, 2026) that Jay asked to be
turned into ReconAnything coverage. Every pattern below was
checked against the live registry first; the detectors here
cover only the gaps the registry did NOT already cover
statically. What Hamonis teaches that is ALREADY covered
(verified by reading the detector code, not by name):
reentrancy (contract_logic "reentrancy", cross_function_
reentrancy, hook_cei_reentrancy), single-source spot oracle
(cp_proto_single_source_oracle), flash-loan lender bugs
(bsc_lending flash_loan_callback_auth_bypass / _repayment_
underflow / _governance_takeover / _reward_dilution / _spot_
balance_check), bridge fake receipts / verifier compromise
(bridge_deposit_event_spoofing, bridge_validator_quorum_
manipulation, bridge_receiver_sender_unchecked), upgrade
with NO gate at all (proxy_upgrade_authorization_gap,
uups_authorize_upgrade_missing), ungated blacklist admin
(bep20_blacklist_authority_check), declared-but-unenforced
mint caps (bep20_mint_cap_bypass), side-door ungated mint
endpoints (bep20_arbitrary_minting_endpoints), owner seizure
of other holders' balances (bep20_owner_privilege_abuse),
permit / allowance abuse as a user surface (permit2_
allowance_abuse, unlimited_allowance_live, scaled_allowance_
overapproval), freeze / blacklist authority as an API check
(rugcheck_freeze_authority, rugcheck_mint_authority), and
honeypots as an API check (rugcheck_honeypot, honeypot.is).
What is NOT a contract-detector matter and is deliberately
not built: 51% attacks and laundering fronts (consensus /
off-chain crime, no contract pattern), and the "don't sign
unlimited approvals" lesson (wallet hygiene, already a user
surface). The 51% / laundering / "how to find a vulnerable
contract" videos teach no static pattern.

- honeypot_sell_gate_static: a token's transfer path blocks
  or taxes SELLS specifically - a blacklist / canSell /
  whitelist mapping read that only bites when the recipient
  is the DEX pair / router (a sell), or a sell fee / sell
  tax of 50% or more applied on the sell path. The Hamonis
  honeypot shape (4 videos): buys work, sells revert or
  lose ~99% to a fee, the chart keeps climbing to lure the
  next victim. Distinct from rugcheck_honeypot (needs the
  honeypot.is API - this one reads verified source, no API),
  from bep20_blacklist_authority_check (fires only when the
  blacklist ADMIN is ungated - a properly gated blacklist
  enforced on sells is invisible to it), and from USDC-style
  blacklists (applied to ALL transfers, not sell-only -
  the protected shape here). A sell fee under 50% does not
  fire; a generic blacklist does not fire.
- oracle_spot_collateral_borrow: a borrow function sizes
  the loan from collateral valued off a single-source spot
  price (DEX pair reserves / balance ratio / spot read)
  with no TWAP, Chainlink, or staleness guard anywhere on
  the path - the Mango Markets shape (Oct 2022, ~$100M+:
  pump the thin spot price with flash-loaned capital, then
  borrow against the inflated valuation in the same
  transaction). Distinct from single_source_oracle (flags
  the spot read alone, medium, no borrow leg) and from
  borrow_no_collateral_check (fires when there is NO
  collateral check at all - this one fires when there IS
  one, but it trusts a manipulable spot price). A TWAP /
  Chainlink / latestRoundData guard is the protected shape.
- upgrade_single_key_admin: an upgrade function
  (upgradeTo / _authorizeUpgrade / setImplementation /
  upgradeBeacon) that IS caller-gated, but only by a
  single-owner check, with no timelock, multisig, Safe,
  or role distribution anywhere in the source - the
  Hamonis upgradeable-proxy + admin-keys lesson (the admin
  can swap the implementation at will; whoever holds the
  one key owns the contract). Distinct from proxy_upgrade_
  authorization_gap (fires only when the upgrade has NO
  gate at all) and from defi_risk single_key_admin (a
  generic domain-plugin heuristic - this is the precise
  static-source detector scoped to upgrade authority).
  A timelock / multisig / role-gated upgrade is the
  protected shape.
- owner_mint_uncapped: a public mint function gated only
  by a single owner, minting to an arbitrary caller-supplied
  address, with NO supply cap declared anywhere in the
  source and no timelock / multisig - the Hamonis mint
  authority lesson (Solana video: retained mint authority
  lets the dev mint +1B tokens and dilute every holder;
  the EVM shape is the same). Distinct from bep20_mint_cap_
  bypass (declared cap, unenforced) and from bep20_
  arbitrary_minting_endpoints (ungated side-door mints -
  this one is the owner-gated mint() itself, which that
  detector explicitly excludes). A cap, a role-gated
  minter, minting only to msg.sender, minting only to a
  fixed treasury, or a mint cadence / cooldown (Compound's
  mintingAllowedAfter shape) is the protected shape.

Gate discipline: the honeypot and oracle detectors use the
batch-28 narrow caller-identity gate (only* modifier,
msg.sender identity comparison, role check suppresses).
The upgrade and mint detectors are trust warnings about
the gate itself, so they REQUIRE a single-owner gate and
fire only when no distributed control exists - they do not
use _skip_fn. The honeypot and mint detectors fire WITHOUT
a recipient classification (batch-20 auction precedent):
a honeypot is a scam warning to buyers, not a stranger-
receivable exploit, and an owner mint is dilution by the
privileged actor, not value a stranger can take.

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
FAMILY = "deep31"

SPECS = [
    S("honeypot_sell_gate_static", FAMILY,
      severity="high", outcome="a", recipient=False,
      detail="Honeypot sell gate (static source): the "
             "token's transfer path blocks or taxes SELLS "
             "specifically - a blacklist / canSell / "
             "whitelist gate that only bites when the "
             "recipient is the DEX pair / router, or a sell "
             "fee / sell tax of 50% or more on the sell "
             "path - so buys work while sells revert or lose "
             "most of their value to a fee. A generic "
             "blacklist applied to all transfers (USDC-style) "
             "and a sell fee under 50% do not flag.",
      fix="Never gate or tax one direction of trade: apply "
          "any transfer restriction symmetrically to buys "
          "and sells, cap sell fees at a small single-digit "
          "percent, and publish the fee schedule on-chain."),
    S("oracle_spot_collateral_borrow", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Spot-priced collateral borrow: a borrow "
             "function sizes the loan from collateral valued "
             "off a single-source spot price (DEX pair "
             "reserves / balance ratio / spot read) with no "
             "TWAP, Chainlink, or staleness guard anywhere "
             "on the path, so flash-loaned capital can pump "
             "the thin spot price and borrow against the "
             "inflated valuation in the same transaction - "
             "the Mango Markets shape. A TWAP / Chainlink / "
             "latestRoundData guard is the protected shape.",
      fix="Never value collateral from a single spot read: "
          "price collateral from a TWAP or a multi-source "
          "oracle with a staleness bound, and cap how much "
          "a single block's price move can change a "
          "borrow limit."),
    S("upgrade_single_key_admin", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="Upgrade authority held by a single key: an "
             "upgrade function (upgradeTo / _authorizeUpgrade "
             "/ setImplementation / upgradeBeacon) is gated "
             "only by a single-owner check, with no "
             "timelock, multisig, Safe, or role distribution "
             "anywhere in the source - whoever holds the one "
             "key can swap the implementation at will and "
             "take over every function and asset behind the "
             "proxy. A timelock / multisig / role-gated "
             "upgrade is the protected shape.",
      fix="Move upgrade authority to a multisig with a "
          "timelock (or a role-gated DAO vote with a delay) "
          "and publish the signers and the delay; users "
          "should never trust an anonymous single-key admin "
          "behind an upgradeable proxy."),
    S("owner_mint_uncapped", FAMILY,
      severity="medium", outcome="a", recipient=False,
      detail="Owner mint with no cap: a public mint function "
             "gated only by a single owner mints to an "
             "arbitrary caller-supplied address, with no "
             "supply cap declared anywhere in the source and "
             "no timelock / multisig - the owner can mint "
             "unlimited tokens to anyone at will and dilute "
             "every holder. A supply cap, a role-gated "
             "minter, minting only to msg.sender, or minting "
             "only to a fixed treasury is the protected shape.",
      fix="Cap the supply on-chain and enforce the cap in "
          "every mint path, or renounce mint authority once "
          "distribution is done; if minting must continue, "
          "gate it behind a multisig with a timelock."),
]
SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16 / deep19 / deep25 / deep28)
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


def _fn_params_typed(fn: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(type, name) parameter pairs from a function signature."""
    sig = fn["signature"]
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    if "(" not in stripped:
        return []
    i = stripped.find("(")
    inner, _ = _balanced(stripped, i)
    out: List[Tuple[str, str]] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append((" ".join(toks[:-1]), toks[-1]))
    return out


def _fn_body(text: str) -> str:
    """The function body (after the first `{`), for searches
    that must not match the signature's own parameter names."""
    i = text.find("{")
    return text[i + 1:] if i >= 0 else text


def _called_internal_texts(fn_text: str, scope) -> str:
    """Text of internal functions this function calls."""
    defined = {f["name"]: f["text"] for f in scope.functions}
    out: List[str] = []
    for m in re.finditer(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                         fn_text):
        name = m.group(1)
        if name in defined and defined[name] not in out:
            out.append(defined[name])
    return "\n".join(out)


def _applied_modifier_bodies(fn: Dict[str, Any], scope) -> str:
    """Bodies of the modifiers applied to this function."""
    sig = fn["signature"]
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i < 0:
        return ""
    _, pend = _balanced(stripped, i)
    tail = stripped[pend + 1:]
    out: List[str] = []
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
        body = scope.modifiers.get(tok)
        if body:
            out.append(body)
    return "\n".join(out)


def _skip_fn(fn: Dict[str, Any], scope) -> bool:
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    return _caller_gated(fn, scope)


_VALUE_MOVE_RE = re.compile(
    r"\.\s*transfer\s*\(|\.\s*transferFrom\s*\(|"
    r"safeTransfer\s*\(|safeTransferFrom\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\.\s*send\s*\(|\.\s*transfer\s*\{\s*value")


def _moves_value(text: str) -> bool:
    """A token / ETH payout of some kind in the function."""
    return bool(_VALUE_MOVE_RE.search(text))


# Distributed control: timelock, multisig, Gnosis Safe, or role
# separation anywhere in the source. "Safe" is matched as a
# whole word so SafeMath / safeTransfer do not count.
_DISTRIBUTED_RE = re.compile(
    r"timelock|TimeLock|multisig|MultiSig|multisignature|"
    r"gnosis|GnosisSafe|\bSafe\b|AccessControl|"
    r"DEFAULT_ADMIN_ROLE|onlyRole|hasRole\s*\(")


def _has_distributed_control(src: str) -> bool:
    return bool(_DISTRIBUTED_RE.search(src))


# ---------------------------------------------------------------------------
# 1. honeypot_sell_gate_static
# ---------------------------------------------------------------------------

_TRANSFER_FN_RE = re.compile(
    r"transfer|_update|_beforeTokenTransfer", re.I)
_GATE_READ_RE = re.compile(
    r"(isBlacklisted|blacklisted|blacklist|black_list|"
    r"blocklist|isBot|canSell|isWhitelisted|whitelisted|"
    r"whitelist)\s*\[")
_SELL_DIR_RE = re.compile(
    r"pair|router|automatedMarketMaker|isSell", re.I)
_SELL_FEE_ASSIGN_RE = re.compile(
    r"\b(sellFee|sellTax|_sellFee|_sellTax)\b\s*=\s*(\d+)")
_FEE_VAR_RE = re.compile(r"\b(sellFee|sellTax|_sellFee|_sellTax)\b")


def _sell_gate_in_window(text: str, pos: int) -> bool:
    """A sell-direction token within +-300 chars of pos."""
    lo = max(0, pos - 300)
    hi = min(len(text), pos + 300)
    return bool(_SELL_DIR_RE.search(text[lo:hi]))


def _analyze_honeypot(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    transfer_fns = [fn for fn in fns
                    if _TRANSFER_FN_RE.search(fn["name"])]
    if not transfer_fns:
        return out
    for fn in transfer_fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"] + "\n" + _called_internal_texts(
            fn["text"], scope)
        # Leg (a): a sell-side gate read.
        for m in _GATE_READ_RE.finditer(text):
            if not _sell_gate_in_window(text, m.start()):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' reads the gate "
                f"'{m.group(1)}' on the transfer path with a "
                f"sell-direction (pair / router) condition "
                f"nearby, so the gate only bites on sells - "
                f"buys pass while sells revert or are blocked. "
                f"Gate analysis: no caller-identity gate on "
                f"the transfer path; the gate is a trade-"
                f"direction filter, not an access control.")
            item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail,
                        "sell-side gate: blacklist / canSell / "
                        "whitelist read on the transfer path "
                        "with a pair/router condition nearby")
            out.append(item)
            break
        if out:
            break
        # Leg (b): a sell fee of 50% or more on the sell path.
        for m in _SELL_FEE_ASSIGN_RE.finditer(src):
            var, val = m.group(1), int(m.group(2))
            if var not in text:
                continue
            # Denominator decides the unit: / 10000 = basis
            # points (>= 5000 is >= 50%), / 100 = percent
            # (>= 50 is >= 50%). No visible denominator: no
            # call - a bare 99 could be 0.99%.
            pct = None
            if re.search(re.escape(var) + r"[^;]{0,120}/ 10000",
                         src):
                pct = val / 100.0
            elif re.search(re.escape(var) + r"[^;]{0,120}/ 100\b",
                           src):
                pct = float(val)
            if pct is None or pct < 50:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' applies the sell "
                f"fee '{var}' ({val}, about {pct:.0f}% of the "
                f"sell) on the transfer path, so most of a "
                f"sell is taken as a fee. Gate analysis: no "
                f"caller-identity gate on the transfer path; "
                f"the fee is a sell-direction tax, not an "
                f"access control.")
            item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail,
                        f"sell fee {pct:.0f}% on the transfer path")
            out.append(item)
            break
        if out:
            break
    return out


# ---------------------------------------------------------------------------
# 2. oracle_spot_collateral_borrow
# ---------------------------------------------------------------------------

_BORROW_FN_RE = re.compile(r"borrow", re.I)
_SPOT_READ_RE = re.compile(
    r"getReserves\s*\(|reserve0\s*/\s*reserve1|"
    r"reserve1\s*/\s*reserve0|"
    r"balanceOf\s*\([^)]*\)\s*/\s*[^;]*balanceOf\s*\(|"
    r"spotPrice|getSpotPrice")
_VALUATION_RE = re.compile(
    r"collateralValue|borrowAmount|accountLiquidity|"
    r"healthFactor|exchangeRate|collateral\s*\w*\s*[Vv]alue|"
    r"getHypotheticalAccountLiquidity")
_ORACLE_GUARD_RE = re.compile(
    r"TWAP|timeWeighted|time-weighted|latestRoundData|"
    r"consult\s*\(|observe\s*\(|AggregatorV3|priceFeed|"
    r"Chainlink|getRoundData|staleness|MAX_DELAY|"
    r"updatedAt", re.I)


def _analyze_oracle_borrow(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _BORROW_FN_RE.search(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = (fn["text"] + "\n" +
                _called_internal_texts(fn["text"], scope) +
                "\n" + _applied_modifier_bodies(fn, scope))
        if not _SPOT_READ_RE.search(text):
            continue
        if not _VALUATION_RE.search(text):
            continue
        if not _moves_value(text):
            continue
        if _ORACLE_GUARD_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' values collateral "
            f"from a single-source spot read and moves value "
            f"to the caller with no TWAP, Chainlink, or "
            f"staleness guard anywhere on the path (function, "
            f"helpers, or modifiers), so the valuation can "
            f"be pumped in the same transaction and borrowed "
            f"against. Gate analysis: no caller-identity "
            f"gate, no oracle guard.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "ungated borrow: spot-priced collateral, "
                    "no TWAP / Chainlink / staleness guard")
        out.append(_finish_recipient(spec, item, text))
        break
    return out


# ---------------------------------------------------------------------------
# 3. upgrade_single_key_admin
# ---------------------------------------------------------------------------

_UPGRADE_FN_RE = re.compile(
    r"upgrade|setImplementation", re.I)


def _analyze_upgrade_admin(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    if _has_distributed_control(src):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _UPGRADE_FN_RE.search(fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        # Ungated upgrades are the proxy_upgrade_
        # authorization_gap lane - this detector is only
        # about upgrades that ARE gated, by one key.
        if not _caller_gated(fn, scope):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' rewrites the "
            f"implementation behind the proxy and is gated "
            f"only by a single-owner check, with no "
            f"timelock, multisig, Safe, or role distribution "
            f"anywhere in the source. Gate analysis: "
            f"caller-identity gate present (single owner) "
            f"but no distributed control.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "upgrade gated only by a single-owner "
                    "check, no timelock / multisig / role")
        out.append(item)
        break
    return out


# ---------------------------------------------------------------------------
# 4. owner_mint_uncapped
# ---------------------------------------------------------------------------

_CAP_RE = re.compile(
    r"maxSupply|MAX_SUPPLY|supplyCap|mintCap|_cap\b|"
    r"MAX_MINT|mintLimit")
_MINT_CALL_RE = re.compile(r"_mint\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)")
# A mint cadence / cooldown (Compound's 30-day mintingAllowedAfter
# shape) is a rate limit on dilution, not an uncapped mint.
_MINT_DELAY_RE = re.compile(
    r"mintingAllowedAfter|lastMint|nextMint|mintDelay|"
    r"mintCooldown|mintInterval", re.I)


def _analyze_owner_mint(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    if _CAP_RE.search(src):
        return []
    if _has_distributed_control(src):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not re.match(r"mint([A-Z_]|$)", fn["name"]):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        if "external" not in fn["signature"] and \
                "public" not in fn["signature"]:
            continue
        # Ungated mints are other detectors' lane; this one
        # is the owner-gated mint with no cap. A mint cadence
        # / cooldown is a rate limit on dilution, not an
        # uncapped mint.
        if not _caller_gated(fn, scope):
            continue
        fn_text = (fn["text"] + "\n" +
                   _called_internal_texts(fn["text"], scope))
        if _MINT_DELAY_RE.search(fn_text):
            continue
        typed = dict((n, t) for t, n in _fn_params_typed(fn))
        body = _fn_body(fn["text"])
        dest = None
        for m in _MINT_CALL_RE.finditer(body):
            cand = m.group(1)
            if cand in typed and "address" in typed[cand]:
                dest = cand
                break
        if dest is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' is gated only by a "
            f"single-owner check and mints to the arbitrary "
            f"caller-supplied address parameter '{dest}', "
            f"with no supply cap declared anywhere in the "
            f"source and no timelock / multisig. Gate "
            f"analysis: caller-identity gate present "
            f"(single owner) but no cap and no distributed "
            f"control.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "owner-only mint to a caller-supplied "
                    "address, no supply cap, no distributed "
                    "control")
        out.append(item)
        break
    return out


ANALYZERS = {
    "honeypot_sell_gate_static": _analyze_honeypot,
    "oracle_spot_collateral_borrow": _analyze_oracle_borrow,
    "upgrade_single_key_admin": _analyze_upgrade_admin,
    "owner_mint_uncapped": _analyze_owner_mint,
}


def analyze_deep31_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-31 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep31_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit31Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 31)"
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
        for item in analyze_deep31_source(
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
                source="deep audit detector batch 31 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit31Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 31) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
