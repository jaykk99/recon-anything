"""Recipient-first detectors (2026-11-03, Jay's diagnosis).

Every legacy drain/mint/withdraw detector searches by DANGEROUS
FUNCTION first, then a later triage step discovers the money lands
at a FIXED or HOLDER-SELF address and a stranger gets $0. All 11 of
the Nov 2 "real candidates" died at exactly that step: ungated code,
probe-proven, but the destination was a hardcoded marketing/dev
wallet. Detection was searching for the wrong shape.

This family inverts the search. The RECEIVER is the primary key:

- A finding only becomes a candidate when the value destination is
  CALLER (msg.sender) or CALLER-SUPPLIED (a caller-controlled
  address parameter), classified from the function itself via
  contract_logic.classify_recipient - recipient classification is
  part of the finding, not a later triage step.
- AND the caller does not have to own/entitle the amount paid out:
  each detector carries its own entitlement analysis (is the payout
  bounded by the caller's own recorded balance/entitlement, and is
  that entitlement consumed?).
- FIXED / HOLDER-SELF variants of the same code come out
  trigger-only at low severity, never candidate-grade.

Six detectors:

- recipient_mint_to_caller: ungated mint landing with the caller.
- recipient_unbacked_claim: claim/reward/faucet paying the caller
  with no backing entitlement, or an entitlement never decremented
  (repeatable / double claim).
- recipient_overdraw_withdraw: withdraw/release where a stranger
  can draw more than their own deposited/credited balance (broken
  entitlement accounting). A holder-self unwrap (WETH shape: the
  caller's own balance is debited by exactly the amount) stays
  silent.
- recipient_rescue_to_param: rescue/sweep/emergency functions
  whose destination is a caller-supplied parameter. The existing
  fleet mostly catches the hardcoded-destination shape, which is
  the trigger-only shape; this one catches the payable shape.
- recipient_bridge_release_unproven: bridge/escrow unlock or
  release to a caller-supplied recipient with no message/deposit
  proof verified in the call path.
- recipient_sig_value_to_self: signature/permit/approval paths
  where a caller can move value to themselves without a valid
  owner signature (no signer comparison at all, or the "signer"
  is itself caller-supplied). Extends the ecrecover_zero_signer
  class from stored state to permit/claim shapes.

Static, verified-source, fast lane, same discipline as the BSC-100
and deep-audit trains: gated or protected shapes stay silent.
Detection only: never sends a transaction, never calls the
contract. Whether a candidate is VERIFIED_REAL is the
auto-validator's job (probe / fork simulation), not this lane's.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import chain_data
from . import contract_chain as cc
from . import contract_logic as cl

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "recipient_first"

# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

SPECS: Dict[str, Dict[str, str]] = {
    "recipient_mint_to_caller": {
        "severity": "high",
        "detail": (
            "Ungated mint to caller: a public mint entry point with "
            "no gate mints tokens straight to msg.sender or a "
            "caller-supplied address. The recipient IS the caller, "
            "and nothing requires the caller to own or pay for the "
            "amount. On any token with a live pool the minted "
            "supply is sellable, so this is a direct value print. "
            "(Pool liveness is confirmed by the validator lane; "
            "the static finding stands on the mint path itself.)"),
        "fix": ("Gate the mint (onlyOwner / minter role), or "
                "remove the public mint path entirely."),
    },
    "recipient_unbacked_claim": {
        "severity": "high",
        "detail": (
            "Claim pays the caller with no backing entitlement: a "
            "claim / reward / faucet function transfers value to "
            "msg.sender (or a caller-supplied address) where the "
            "payout is not bounded by the caller's own recorded "
            "entitlement, or the entitlement is read but never "
            "decremented or marked consumed - so the claim is "
            "repeatable (double claim) by any stranger, forever, "
            "until the contract is empty."),
        "fix": ("Record a per-caller entitlement, bound the payout "
                "by it, and decrement / mark it consumed BEFORE "
                "paying out (checks-effects-interactions)."),
    },
    "recipient_overdraw_withdraw": {
        "severity": "high",
        "detail": (
            "Withdraw exceeds the caller's own balance: a withdraw "
            "/ release / redeem function pays msg.sender an amount "
            "that is not bounded by the caller's own deposited or "
            "credited balance - no require checks the amount "
            "against the caller's recorded balance and the payout "
            "is not debited from it either. A stranger with a zero "
            "deposit can name an amount up to the whole contract "
            "balance. This is NOT a holder-self unwrap: an unwrap "
            "debits the caller's own balance by exactly the amount "
            "paid, and that shape stays silent here."),
        "fix": ("Bound every withdrawal by the caller's recorded "
                "balance (require amount <= balance) and debit that "
                "balance before paying out."),
    },
    "recipient_rescue_to_param": {
        "severity": "high",
        "detail": (
            "Rescue pays a caller-supplied destination: a rescue / "
            "sweep / emergency-withdraw function with no gate "
            "moves the contract's tokens or native balance to an "
            "address the CALLER passes in. Anyone can point the "
            "contract's whole stuck balance at their own wallet. "
            "(The hardcoded-destination variant of this shape is "
            "trigger-only - the money can only ever land at the "
            "project wallet - and stays out of this finding.)"),
        "fix": ("Gate rescue functions to the owner and fix the "
                "destination to a governed treasury address."),
    },
    "recipient_bridge_release_unproven": {
        "severity": "high",
        "detail": (
            "Bridge/escrow release without proof: an unlock / "
            "release / finalize function pays a caller-supplied "
            "recipient, and nothing in the call path verifies a "
            "bridge message, deposit proof, Merkle proof, "
            "validator signature, or consumes a message nonce. "
            "The release is authorized by the call itself, so any "
            "stranger can release escrowed value to themselves."),
        "fix": ("Require and verify the bridge message / deposit "
                "proof (validator quorum or Merkle proof), bind "
                "the recipient to the proven message, and consume "
                "the message nonce before releasing."),
    },
    "recipient_sig_value_to_self": {
        "severity": "high",
        "detail": (
            "Signature path moves value to the caller without a "
            "valid owner signature: a permit / claim / signed-"
            "withdraw function moves value to msg.sender (or a "
            "caller address) while the recovered signer is never "
            "compared to a stored owner/authority, or the expected "
            "signer is itself a caller-supplied parameter (pass "
            "address(0) as the signer and any garbage signature "
            "recovers to it). No valid owner signature is needed "
            "to take the value."),
        "fix": ("Recover the signer with a library that reverts "
                "on invalid signatures (OpenZeppelin ECDSA.recover)"
                ", require the recovered address to be non-zero "
                "and equal to a STORED owner/authority, and bind "
                "the signature to a consumed nonce."),
    },
}


# ---------------------------------------------------------------------------
# Shared analysis helpers
# ---------------------------------------------------------------------------

_PAYOUT_RE = re.compile(
    r"\.\s*(transfer|send|call)\s*(\{[^}]*\})?\s*\(|"
    r"\b(_mint|_safeMint|safeTransfer|transferFrom|safeTransferFrom)"
    r"\s*\(", re.I)
_MINT_CALL_RE = re.compile(r"\b(_mint|_safeMint|mint)\s*\(", re.I)
_ENT_READ_RE = re.compile(
    r"([A-Za-z_]\w*)\s*\[\s*(msg\.sender|_msgSender\(\))\s*\]|"
    r"\b(balanceOf|sharesOf|balance)\s*\(\s*(msg\.sender|"
    r"_msgSender\(\))\s*\)", re.I)


def _fns(src: str, contract_name: str = ""):
    scope = cl._Scope(src, contract_name)
    fns = [fn for fn in scope.functions if "{" in fn["text"]]
    return scope, fns


def _public(fn: Dict[str, Any]) -> bool:
    sig = fn["signature"]
    if re.search(r"\b(internal|private)\b", sig):
        return False
    return bool(re.search(r"\b(public|external)\b", sig))


def _pays_out(fn_text: str) -> bool:
    return bool(_PAYOUT_RE.search(fn_text))


def _recipient(fn_text: str) -> Tuple[str, str]:
    return cl.classify_recipient(fn_text)


def _path(scope, fn: Dict[str, Any]) -> Tuple[str, str, str]:
    """(path_text, recipient, detail) over the argument-bound
    internal call path of fn: payout detection and recipient
    classification run over the bound path, so an entry whose
    helper performs the transfer (withdraw -> _payout ->
    msg.sender) is read from the actual call path, not from
    the entry body alone."""
    recipient, detail, text = cl.classify_recipient_path(scope, fn)
    return text, recipient, detail





def _caller_indexed_reads(fn_text: str) -> List[str]:
    """State mappings / balance views read keyed by the caller."""
    out = []
    for m in _ENT_READ_RE.finditer(fn_text):
        out.append(m.group(1) or m.group(3))
    return out


def _caller_indexed_write(fn_text: str, names: List[str]) -> bool:
    """Is any caller-keyed entitlement consumed in this function?

    Consumed means: decremented (-= amount), zeroed (= 0), deleted,
    or a claimed-flag set to true for the caller.
    """
    for name in names:
        pat = re.compile(
            re.escape(name) +
            r"\s*\[\s*(msg\.sender|_msgSender\(\))\s*\]\s*"
            r"(-=|=|\+=)", re.I)
        for m in pat.finditer(fn_text):
            rhs = fn_text[m.end():m.end() + 24]
            if m.group(2) == "-=":
                return True
            if m.group(2) == "=" and re.match(
                    r"\s*(0\b|true\b|false\b)", rhs):
                return True
    if re.search(r"delete\s+\w+\s*\[\s*msg\.sender\s*\]", fn_text):
        return True
    return False


def _amount_bounded(fn_text: str, names: List[str]) -> bool:
    """require/if-revert comparing an amount against a caller-keyed
    balance before payout (the canonical entitled-withdraw shape),
    or the caller's balance debited by the payout amount."""
    for name in names:
        ent = (re.escape(name) +
               r"\s*(\[\s*(msg\.sender|_msgSender\(\))\s*\]|"
               r"\(\s*(msg\.sender|_msgSender\(\))\s*\))")
        if re.search(r"(require|assert)\s*\([^;]*" + ent +
                     r"[^;]*(>=|>|==)|"
                     r"(require|assert)\s*\([^;]*(>=|<=|>|<)[^;]*" +
                     ent, fn_text, re.I):
            return True
        # debit-by-amount of the caller's own balance (WETH unwrap
        # and entitled withdraw shapes)
        if re.search(ent + r"\s*(-=)", fn_text, re.I):
            return True
    return False


def _hit(spec_id: str, fn: Dict[str, Any], extra: str,
         recipient: str, report_class: str) -> Dict[str, Any]:
    spec = SPECS[spec_id]
    sev = spec["severity"] if report_class == "candidate" else "low"
    detail = spec["detail"] + " " + extra
    if report_class == "trigger_only":
        detail += (
            " Recipient analysis: the value destination is not "
            "caller-reachable, so a stranger can trigger this but "
            "receives nothing - TRIGGER-ONLY under the receive "
            "rule.")
    return {"kind": spec_id, "severity": sev, "function": fn["name"],
            "code": cc._snip(fn["text"]), "detail": detail,
            "recipient": recipient, "report_class": report_class,
            "remediation": spec["fix"]}


def _finish(spec_id: str, fn: Dict[str, Any], extra: str,
            recipient: str) -> List[Dict[str, Any]]:
    """Caller-reachable recipients become candidates; FIXED /
    HOLDER-SELF / UNRESOLVED become trigger-only, never hits."""
    if recipient in ("CALLER", "CALLER-SUPPLIED"):
        return [_hit(spec_id, fn, extra, recipient, "candidate")]
    return [_hit(spec_id, fn, extra, recipient, "trigger_only")]


# ---------------------------------------------------------------------------
# 1. Ungated mint to caller
# ---------------------------------------------------------------------------

def _analyze_mint(src, spec_id, compiler, contract_name):
    scope, fns = _fns(src, contract_name)
    out = []
    for fn in fns:
        if not _public(fn):
            continue
        if not re.search(r"mint", fn["name"], re.I):
            continue
        path_text, recipient, rdetail = _path(scope, fn)
        if not _MINT_CALL_RE.search(path_text):
            continue
        if cl._gated_deep(fn, scope):
            continue
        if "balanceOf(address(this))" in path_text:
            continue  # AMM pair mint: liquidity is metered
            # by the pair's own balance deltas against
            # reserves, i.e. by what the caller already
            # transferred in - not unbacked printing
        if recipient == "HOLDER-SELF" and not re.search(
                r"(require|assert)\s*\([^;]*(balanceOf|balances|"
                r"shares)\s*\[\s*msg\.sender", path_text):
            # The generic classifier reads a mint CREDIT to the
            # caller's balance as self-metering. A mint is not the
            # caller's own money coming back: it is new value
            # printed to the caller, unbounded by anything they
            # hold (no balance bound on the amount, checked
            # above). Reclassify as CALLER.
            recipient = "CALLER"
            rdetail += ("; mint credit reclassified: minted "
                        "value is new value to the caller, not "
                        "the caller's own balance returned")
        if recipient in ("CALLER", "CALLER-SUPPLIED"):
            # Canonical public-surface shapes (the contract_
            # logic FP-elimination read): an ERC4626 mint whose
            # path pulls the caller's own assets in first, a
            # mint authorized by a state-held external contract
            # (Comptroller.mintAllowed), or a mint metered by
            # the contract's own balance deltas is bought /
            # authorized issuance, not unbacked printing.
            reason = cl._fp_downgrade_reason(
                path_text, scope,
                cl.state_variables(scope.scoped_text))
            if reason:
                recipient = "HOLDER-SELF"
                rdetail += f"; downgraded: {reason}"
        extra = (f"Observed: '{fn['name']}' mints with no gate; "
                 f"recipient classified {recipient} ({rdetail}).")
        out.extend(_finish(spec_id, fn, extra, recipient))
    return out


# ---------------------------------------------------------------------------
# Shared boundedness / backing recognition (FP elimination,
# 2026-11-05): shapes where the payout is metered by the
# caller's own recorded position or authorized by a verified
# proof / signature, so it is not a stranger-reachable drain.
# ---------------------------------------------------------------------------

_BURN_CALLER_RE = re.compile(
    r"_burn\s*\(\s*(msg\.sender|_msgSender\(\s*\))")
_PTR_CALLER_RE = re.compile(
    r"(\w+)\s+storage\s+(\w+)\s*=\s*[^;]*"
    r"\[\s*msg\.sender\s*\]")
_PROOF_VERIFY_COND_RE = re.compile(
    r"(?:require|if)\s*\([^;]*?(?:verify|Verify|"
    r"isValidSignature|processProof|MerkleProof)")


def _burn_bounded(text: str) -> bool:
    """The function burns the caller's own tokens / shares:
    the payout cannot exceed what the caller holds (the
    burn reverts otherwise). ERC20Wrapper unwrap and
    share-burning vault withdraws live here."""
    return bool(_BURN_CALLER_RE.search(text))


def _record_debit_bounded(text: str) -> bool:
    """A storage pointer bound to the caller's own record
    (userInfo[pid][msg.sender] and kin) has a field debited
    or zeroed in the function: the payout is metered by
    the caller's recorded balance (MasterChef shape)."""
    for m in _PTR_CALLER_RE.finditer(text):
        ptr = re.escape(m.group(2))
        if re.search(r"\b" + ptr + r"\.\w+\s*(-=|=\s*0\b)",
                     text):
            return True
    return False


def _proof_or_sig_backed(text: str) -> bool:
    """The payout is authorized by evidence the caller must
    present: a proof / signature verification inside a
    require or if condition, or a recovered signer compared
    against a stored authority. A signature that is merely
    recovered and zero-checked - never compared to any
    authority - authorizes nothing and does NOT count."""
    if _PROOF_VERIFY_COND_RE.search(text):
        return True
    return bool(_STORED_SIGNER_CMP_RE.search(text))


# ---------------------------------------------------------------------------
# 2. Unbacked / repeatable claim
# ---------------------------------------------------------------------------

_CLAIM_NAME_RE = re.compile(
    r"claim|faucet|airdrop|reward|drip|bonus|stipend", re.I)


def _analyze_claim(src, spec_id, compiler, contract_name):
    scope, fns = _fns(src, contract_name)
    out = []
    for fn in fns:
        if not _public(fn):
            continue
        if not _CLAIM_NAME_RE.search(fn["name"]):
            continue
        path_text, recipient, rdetail = _path(scope, fn)
        if not _pays_out(path_text):
            continue
        # NOT _gated_deep here: the shared gate read treats an
        # entitlement read + a require on it as a gate, but an
        # entitlement existence check is not an access gate - it
        # is exactly the shape this detector adjudicates below.
        # Access gates (owner/role modifiers, caller-vs-authority
        # checks) still suppress.
        if _access_gated(fn, scope):
            continue
        if _proof_or_sig_backed(path_text):
            continue  # proof / authority-signed entitlement
        reads = _caller_indexed_reads(path_text)
        if reads and _caller_indexed_write(path_text, reads):
            continue  # entitlement read AND consumed: entitled
        if reads:
            extra = (f"Observed: '{fn['name']}' reads the caller's "
                     f"entitlement ({', '.join(sorted(set(reads)))})"
                     " but never decrements or marks it consumed - "
                     "the claim is repeatable. ")
        else:
            extra = (f"Observed: '{fn['name']}' pays out with no "
                     "caller entitlement read at all. ")
        extra += f"Recipient classified {recipient} ({rdetail})."
        out.extend(_finish(spec_id, fn, extra, recipient))
    return out


# ---------------------------------------------------------------------------
# 3. Overdraw withdraw (bounded-by-own-balance analysis)
# ---------------------------------------------------------------------------

_WITHDRAW_NAME_RE = re.compile(
    r"withdraw|release|redeem|unstake|exit|unwrap", re.I)


def _analyze_overdraw(src, spec_id, compiler, contract_name):
    scope, fns = _fns(src, contract_name)
    out = []
    for fn in fns:
        if not _public(fn):
            continue
        if not _WITHDRAW_NAME_RE.search(fn["name"]):
            continue
        path_text, recipient, rdetail = _path(scope, fn)
        if not _pays_out(path_text):
            continue
        if cl._gated_deep(fn, scope):
            continue
        reads = _caller_indexed_reads(path_text)
        if reads and _amount_bounded(path_text, reads):
            continue  # entitled withdraw / holder-self unwrap
        # A debit of the caller's own balance by name-less internal
        # balance vars (balanceOf-keyed) also bounds the payout.
        if _amount_bounded(path_text, ["balanceOf", "_balances",
                                       "balances"]):
            continue
        if _burn_bounded(path_text) or \
                _record_debit_bounded(path_text):
            continue  # payout metered by the caller's own
            # burned shares / debited recorded balance
        if _PROOF_VERIFY_COND_RE.search(path_text):
            continue  # release authorized by a verified
            # proof / signature (ERC-1271 release shape)
        extra = (f"Observed: '{fn['name']}' pays out with no bound "
                 "against the caller's own recorded balance and no "
                 "debit of it. "
                 f"Recipient classified {recipient} ({rdetail}).")
        out.extend(_finish(spec_id, fn, extra, recipient))
    return out


# ---------------------------------------------------------------------------
# 4. Rescue / sweep to caller-supplied destination
# ---------------------------------------------------------------------------

_RESCUE_NAME_RE = re.compile(
    r"rescue|sweep|emergency|recover|stuck|salvage", re.I)


def _analyze_rescue(src, spec_id, compiler, contract_name):
    scope, fns = _fns(src, contract_name)
    out = []
    for fn in fns:
        if not _public(fn):
            continue
        if not _RESCUE_NAME_RE.search(fn["name"]):
            continue
        path_text, recipient, rdetail = _path(scope, fn)
        if not _pays_out(path_text) and "selfdestruct" not in \
                path_text:
            continue
        if cl._gated_deep(fn, scope):
            continue
        if _burn_bounded(path_text) or \
                _record_debit_bounded(path_text):
            continue  # caller collecting their own recorded
            # position (emergencyWithdraw shape), not a rescue
        extra = (f"Observed: '{fn['name']}' moves contract value "
                 f"with no gate; destination classified "
                 f"{recipient} ({rdetail}).")
        out.extend(_finish(spec_id, fn, extra, recipient))
    return out


# ---------------------------------------------------------------------------
# 5. Bridge / escrow release without proof
# ---------------------------------------------------------------------------

_BRIDGE_FN_RE = re.compile(
    r"unlock|release|finalize|execute|relay|completebridge|"
    r"processmessage|withdraw", re.I)
_PROOF_RE = re.compile(
    r"ecrecover|ECDSA|verify\s*\(|merkle|proof|signature|"
    r"validator|quorum|threshold", re.I)
_NONCE_CONSUME_RE = re.compile(
    r"(processed|executed|claimed|used|consumed)\w*\s*(\[|=)", re.I)


def _analyze_bridge(src, spec_id, compiler, contract_name):
    scope, fns = _fns(src, contract_name)
    scoped = scope.scoped_text
    bridge_ctx = bool(re.search(
        r"bridge|escrow|message|nonce|relayer|validator", scoped,
        re.I))
    out = []
    for fn in fns:
        if not _public(fn):
            continue
        if not _BRIDGE_FN_RE.search(fn["name"]):
            continue
        path, recipient, rdetail = _path(scope, fn)
        if not _pays_out(path):
            continue
        if cl._gated_deep(fn, scope):
            continue
        if not bridge_ctx:
            continue
        # Proof verified anywhere in the (bound) call path
        # suppresses: the function itself or a helper it calls
        # checks a proof or consumes a message id.
        if _PROOF_RE.search(path) or _NONCE_CONSUME_RE.search(path):
            continue
        extra = (f"Observed: '{fn['name']}' releases escrowed "
                 "value with no proof verification and no nonce "
                 "consumption in its call path. "
                 f"Recipient classified {recipient} ({rdetail}).")
        out.extend(_finish(spec_id, fn, extra, recipient))
    return out


# ---------------------------------------------------------------------------
# 6. Signature path moving value to self without a valid signer
# ---------------------------------------------------------------------------

_SIG_FN_HINT_RE = re.compile(
    r"permit|claim|withdraw|redeem|mint|execute|relay", re.I)
_SIG_MATERIAL_RE = re.compile(
    r"ecrecover|ECDSA\.recover|signature|uint8\s+v\b|bytes32\s+r\b",
    re.I)
_STORED_SIGNER_CMP_RE = re.compile(
    r"(recovered|signer|recoveredAddress|_signer)\w*\s*(==|!=)\s*"
    r"(owner|authority|signer|_signer|admin|treasury|validator|"
    r"verifyingSigner|authorizedSigner|trustedSigner|feeSigner|"
    r"signerAddress)\b|"
    r"(owner|authority|validator)\w*\s*(==|!=)\s*"
    r"(recovered|signer)", re.I)


def _sig_gated(fn: Dict[str, Any], scope) -> bool:
    """Gate check for the signature class. The generic gate read
    treats the mere presence of ecrecover as a gate (a signature
    check EXISTS), which would silence this whole class - here the
    question is whether access is gated by something OTHER than
    the signature path under analysis: an owner/role modifier, a
    modifier definition with a caller check, or a body check of
    msg.sender against a stored authority."""
    sig = fn["signature"]
    if cc._GATE_RE.search(sig) or \
            re.search(r"\bonly[A-Z][A-Za-z0-9_]*\b", sig):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        tail = stripped[cd_matching_tail(stripped, i):]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and re.search(
                    r"msg\.sender\s*(==|!=)|_checkOwner|hasRole",
                    body):
                return True
    return bool(re.search(
        r"msg\.sender\s*(==|!=)\s*(owner|admin|authority|"
        r"treasury)\b|(owner|admin|authority)\s*(==|!=)\s*"
        r"msg\.sender", fn["text"]))


# The claim detector uses the same access-gate-only check.
_access_gated = _sig_gated


def cd_matching_tail(sig: str, i: int) -> int:
    """Index just past the parameter list's closing paren."""
    depth = 0
    for j in range(i, len(sig)):
        if sig[j] == "(":
            depth += 1
        elif sig[j] == ")":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(sig)


def _analyze_sig(src, spec_id, compiler, contract_name):
    scope, fns = _fns(src, contract_name)
    out = []
    for fn in fns:
        if not _public(fn):
            continue
        if not _SIG_FN_HINT_RE.search(fn["name"]):
            continue
        if not _SIG_MATERIAL_RE.search(fn["text"]):
            continue
        path_text, path_recipient, path_rdetail = _path(scope, fn)
        if not _pays_out(path_text):
            continue
        if _sig_gated(fn, scope):
            continue
        text = fn["text"]
        # Caller-supplied expected signer: the "check" compares
        # the recovered address against an address PARAMETER, so
        # the caller chooses both sides of the comparison.
        sig = fn["signature"]
        params = sig[sig.find("(") + 1:sig.rfind(")")] \
            if "(" in sig else ""
        addr_params = re.findall(r"address\s+(?:payable\s+)?(\w+)",
                                 params)
        supplied_signer = None
        for p in addr_params:
            if re.search(r"(recovered|ecrecover[^;]*)\s*(==|!=)\s*" +
                         re.escape(p) + r"\b", text) or \
               re.search(r"\b" + re.escape(p) +
                         r"\b\s*(==|!=)\s*(recovered|ecrecover)",
                         text):
                supplied_signer = p
                break
        stored_cmp = bool(_STORED_SIGNER_CMP_RE.search(text))
        zero_checked = bool(re.search(
            r"(recovered|signer)\w*\s*!=\s*address\s*\(\s*0\s*\)|"
            r"address\s*\(\s*0\s*\)\s*!=\s*(recovered|signer)", text))
        uses_safe_recover = "ECDSA.recover" in text
        if supplied_signer is None and stored_cmp and \
                (zero_checked or uses_safe_recover):
            continue  # canonical checked shape
        if supplied_signer is None and not stored_cmp:
            extra = (f"Observed: '{fn['name']}' uses signature "
                     "material and moves value, but the recovered "
                     "signer is never compared to a stored owner "
                     "or authority. ")
        elif supplied_signer is not None:
            extra = (f"Observed: '{fn['name']}' compares the "
                     f"recovered signer against '{supplied_signer}'"
                     ", an address parameter the caller supplies - "
                     "the caller picks both sides of the check. ")
        else:
            continue  # stored comparison exists; the zero-signer
            # class (deep_audit ecrecover_zero_signer) covers the
            # remaining stored-signer-no-zero-check shape.
        recipient, rdetail = path_recipient, path_rdetail
        extra += f"Recipient classified {recipient} ({rdetail})."
        out.extend(_finish(spec_id, fn, extra, recipient))
    return out


ANALYZERS = {
    "recipient_mint_to_caller": _analyze_mint,
    "recipient_unbacked_claim": _analyze_claim,
    "recipient_overdraw_withdraw": _analyze_overdraw,
    "recipient_rescue_to_param": _analyze_rescue,
    "recipient_bridge_release_unproven": _analyze_bridge,
    "recipient_sig_value_to_self": _analyze_sig,
}


def analyze_recipient_source(src: str, spec_id: str,
                             compiler: str = "",
                             contract_name: str = ""
                             ) -> List[Dict[str, Any]]:
    """Run ONE recipient-first detector over verified source.

    Returns finding dicts carrying recipient + report_class
    (candidate | trigger_only) as first-class fields.
    """
    fn = ANALYZERS.get(spec_id)
    if fn is None:
        return []
    try:
        return fn(src, spec_id, compiler, contract_name)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Plugin classes (one registered plugin per detector)
# ---------------------------------------------------------------------------

class RecipientFirstPlugin(Plugin):
    """Base for the recipient-first family. run() mirrors the
    contract_logic collection/source-fetch path; the analysis is
    analyze_recipient_source with this plugin's own spec only."""
    id = ""
    label = "Recipient First"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = ""
    phase = 2
    timeout_s = 120
    _spec_id: str = ""

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec_id = self._spec_id
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. "
                "bsc:0x...) or a web target whose pages reference "
                "one")
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
        hits = sum(1 for f in findings
                   if f.key == spec_id and
                   (f.evidence or {}).get("report_class") == "candidate")
        res = self._ok(
            findings,
            f"{spec_id}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - skipped, no "
            f"guess made), {hits} candidate finding(s)")
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
        spec_id = self._spec_id
        if chain_hint:
            chain_ids = [chain_hint]
        else:
            chain_ids = list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        got_source = False
        rpc_all_failed = True
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await chain_data.get_code(ctx, chain, addr)
            if code is None:
                continue
            rpc_all_failed = False
            if code == "0x" or len(code) < 4:
                continue
            pairs += 1
            src = await chain_data.get_source(ctx, chain, addr,
                                              key)
            if src:
                got_source = True
                items = analyze_recipient_source(
                    src["source"], spec_id,
                    src.get("compiler", ""),
                    src.get("contract_name", ""))
                url = cc.explorer_url(chain, addr)
                for item in items:
                    ev = {"severity": item["severity"],
                          "address": addr, "chain": chain.id,
                          "chain_id": chain.chain_id,
                          "check": spec_id,
                          "function": item["function"],
                          "code": item["code"],
                          "detail": item["detail"],
                          "recipient": item["recipient"],
                          "report_class": item["report_class"],
                          "source_origin": src.get("origin", ""),
                          "remediation": item["remediation"]}
                    findings.append(self._f(
                        "web3", spec_id,
                        f"{item['severity'].upper()}: "
                        f"{item['detail']}",
                        source=f"verified source ({src.get('origin', '')})",
                        source_url=url, confidence=85, evidence=ev,
                        passive=True))
            if chain_hint:
                break
        if pairs == 0 and rpc_all_failed:
            findings.append(self._f(
                "web3", f"{spec_id}_failed",
                f"MEDIUM: {addr}: every public RPC endpoint "
                "failed, so no chain data could be retrieved. No "
                "conclusion drawn.",
                source="public JSON-RPC eth_getCode",
                confidence=60, passive=True,
                evidence={"severity": "medium", "address": addr,
                          "remediation": "Retry later; the public "
                                         "RPC endpoints for this "
                                         "chain were "
                                         "unreachable."}))
        return pairs, got_source


def _make_plugin(spec_id: str, class_name: str):
    spec = SPECS[spec_id]
    cls = type(class_name, (RecipientFirstPlugin,), {
        "id": spec_id,
        "label": " ".join(w.capitalize()
                          for w in spec_id.split("_")),
        "description": spec["detail"],
        "_spec_id": spec_id,
        "__module__": __name__,
    })
    return cls


RecipientMintToCallerPlugin = _make_plugin(
    "recipient_mint_to_caller", "RecipientMintToCallerPlugin")
RecipientUnbackedClaimPlugin = _make_plugin(
    "recipient_unbacked_claim", "RecipientUnbackedClaimPlugin")
RecipientOverdrawWithdrawPlugin = _make_plugin(
    "recipient_overdraw_withdraw", "RecipientOverdrawWithdrawPlugin")
RecipientRescueToParamPlugin = _make_plugin(
    "recipient_rescue_to_param", "RecipientRescueToParamPlugin")
RecipientBridgeReleasePlugin = _make_plugin(
    "recipient_bridge_release_unproven",
    "RecipientBridgeReleasePlugin")
RecipientSigValueToSelfPlugin = _make_plugin(
    "recipient_sig_value_to_self", "RecipientSigValueToSelfPlugin")
