"""Deep-audit detectors, batch 5: ERC + access slices (2026-11-04).

Twelve chain-agnostic EVM detectors built to the batch-1/2/3/4
standard: recipient classification computed inside the detector
and carried on the finding (CALLER / CALLER-SUPPLIED = candidate;
FIXED / HOLDER-SELF = trigger-only, never a candidate; pure
configuration findings with no value destination in evidence
stay UNRESOLVED and therefore candidate-grade at the spec
severity), the exact code plus a gate analysis on every finding,
and a finding shape the auto-validator can consume unchanged
(kind, function, recipient, report_class, gate).

Each detector ports the slice the coverage audit
(~/workspace/recon-100-2026-11-04/coverage-a.json) found missing
or partial, and nothing the existing registry already owns:

- erc20_missing_return_guard (ERC-001 slice): callers that wrap
  a standard-interface transfer / transferFrom / approve call
  directly in require / assert / if, on a contract that never
  uses SafeERC20 - that shape compiles against IERC20's bool
  return but REVERTS on no-return tokens such as USDT, whose
  transfer returns nothing at all. Plus the mirror slice no
  detector owned: a token-shaped contract (balanceOf +
  totalSupply) whose own transfer / transferFrom signature has
  no returns clause at all.
- erc721_mint_without_receiver_check (ERC-002 slice): an
  ERC721 mint path that calls plain _mint(recipientParam, ...)
  with a caller-supplied recipient and never calls _safeMint
  nor checks onERC721Received on that path - tokens minted to
  a contract that cannot handle them are locked forever.
- erc1155_batch_receiver_missing (ERC-003): a contract that IS
  an ERC-1155 receiver (it defines onERC1155Received) but does
  NOT define onERC1155BatchReceived, so every batch transfer
  to it fails / locks.
- eip712_separator_unbound (ERC-004 slice + CRY-003 slice): a
  signature-verification / permit path whose domain separator
  is cached once (constructor assignment, immutable, state var
  never recomputed from block.chainid at verify time) - after
  a chain fork the cached separator replays on both chains -
  or constructed with no chainId term at all.
- erc2771_msg_sender_unbound (ERC-006): a contract that trusts
  a forwarder (isTrustedForwarder / trustedForwarder) but has
  no _msgSender() override extracting the calldata-suffix
  sender, or an override that ignores the forwarder - so
  authorization still runs on the forwarder's raw msg.sender.
- eip1271_magic_value_unchecked (ERC-008 slice): a function
  calls isValidSignature(...) on an external contract and
  uses the result without ever comparing it to the EIP-1271
  magic value 0x1626ba7e (or an IERC1271 magic constant) in
  the same function.
- two_step_ownership_missing (ACC-002): transferOwnership
  assigns the owner state var directly, with no pendingOwner
  record and no acceptOwnership step (no Ownable2Step shape),
  so a typo'd address irreversibly bricks control.
- default_admin_grant_exposed (ACC-004 slice):
  DEFAULT_ADMIN_ROLE granted to a hardcoded literal address
  anywhere, or granted inside an initialize-style function
  (a re-initialization / front-run surface), instead of only
  to msg.sender in the constructor.
- renounce_role_last_admin (ACC-005 slice): a renounceRole
  definition / override whose body performs no
  remaining-holder check (no getRoleMemberCount, no hasRole
  guard on another holder), so the last admin can renounce
  and brick role administration forever.
- pause_coverage_missing (ACC-006): a contract WITH pause
  machinery whose public / external value-moving functions
  carry no whenNotPaused / _requireNotPaused / paused guard -
  one finding per unguarded function; the emergency pause
  does not stop the operations it exists to stop.
- signature_nonce_unconsumed (ACC-007 slice): a nonce state
  var / mapping READ inside a signed-digest / verify path
  (ecrecover or ECDSA.recover present) but NEVER written,
  incremented or assigned anywhere in the contract, so the
  "nonce" never actually prevents replay. Name-agnostic
  about the function; the check is read-vs-write on the
  nonce identifier itself.
- multisig_threshold_setter_unsafe (ACC-010 slice): a
  multisig-shaped contract (owners array / isOwner mapping)
  with a function assigning the threshold / required /
  numConfirmations var that is ungated OR unbounded (no
  require bounding it to 0 < v <= owners count) - threshold
  0 means no-sig execution, above the owner count means a
  permanent brick.

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
FAMILY = "deep5"

SPECS = [
    S("erc20_missing_return_guard", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="ERC20 return value handled unsafely for "
             "no-return tokens: either a standard-interface "
             "transfer / transferFrom / approve call is wrapped "
             "directly in a require / assert / if on a contract "
             "that never uses SafeERC20 (that shape reverts on "
             "tokens such as USDT whose transfer returns "
             "nothing at all), or this token-shaped contract's "
             "own transfer / transferFrom signature declares "
             "no return value, so every bool-expecting caller "
             "breaks against it.",
      fix="Route every external token call through "
          "SafeERC20 (safeTransfer / safeTransferFrom / "
          "safeApprove), which tolerates missing return "
          "values, and make token implementations declare "
          "returns (bool) on transfer / transferFrom."),
    S("erc721_mint_without_receiver_check", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="ERC721 mint without a receiver check: a public "
             "/ external mint function calls plain _mint with "
             "a caller-supplied recipient and the mint path "
             "never calls _safeMint nor checks "
             "onERC721Received. _mint performs no receiver "
             "callback, so tokens minted to a contract that "
             "cannot handle ERC721 are locked in it forever.",
      fix="Mint with _safeMint (or explicitly verify "
          "onERC721Received returns the ERC721 magic value "
          "for contract recipients) on every mint path that "
          "accepts an arbitrary recipient."),
    S("erc1155_batch_receiver_missing", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Incomplete ERC-1155 receiver: the contract "
             "defines onERC1155Received, so senders treat it "
             "as a 1155 receiver, but it does NOT define "
             "onERC1155BatchReceived. Batch transfers to this "
             "contract revert or strand the tokens - the "
             "acceptance surface is half implemented.",
      fix="Implement onERC1155BatchReceived (returning its "
          "magic value 0xbc197c81) alongside "
          "onERC1155Received, or stop advertising ERC-1155 "
          "receiver support."),
    S("eip712_separator_unbound", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="EIP-712 domain separator not bound to the live "
             "chain: the separator used by a signature / "
             "permit path is cached once (constructor, "
             "immutable or state variable) and never "
             "recomputed from block.chainid at verify time, "
             "or it is constructed with no chainId term at "
             "all. After a chain fork - or on any chain where "
             "the contract is redeployed at the same address "
             "- signatures replay across chains because the "
             "separator no longer distinguishes them.",
      fix="Compute the domain separator at call time from "
          "block.chainid (the OpenZeppelin EIP712 pattern: "
          "cache the chain id alongside the separator and "
          "recompute whenever block.chainid differs), and "
          "always include chainId in the domain."),
    S("erc2771_msg_sender_unbound", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="ERC-2771 trusted forwarder without a bound "
             "sender: the contract references a trusted "
             "forwarder but has no _msgSender() override "
             "extracting the calldata-suffix sender (or the "
             "override ignores the forwarder). Meta-"
             "transactions therefore authorize on the "
             "forwarder's own raw msg.sender - either every "
             "relayed call is treated as the forwarder, or "
             "the relayed identity is never recovered at all.",
      fix="Inherit ERC2771Context (or replicate it): "
          "override _msgSender() / _msgData() so that, when "
          "msg.sender is the trusted forwarder and calldata "
          "carries the 20-byte suffix, the suffix address is "
          "the effective sender."),
    S("eip1271_magic_value_unchecked", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="EIP-1271 result used without the magic-value "
             "check: a function calls isValidSignature(...) "
             "on an external contract and uses the result "
             "without comparing it to the magic value "
             "0x1626ba7e (or an IERC1271 magic constant) in "
             "the same function. A contract signer returning "
             "any other bytes4 - including a truthy-looking "
             "or partially-matching value - is treated as a "
             "valid signature.",
      fix="Require the exact magic value: "
          "require(signer.isValidSignature(hash, signature) "
          "== 0x1626ba7e) (IERC1271's magic constant), and "
          "fail closed on any other return."),
    S("two_step_ownership_missing", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="Single-step ownership transfer: "
             "transferOwnership assigns the owner state "
             "variable directly in its body, and the contract "
             "has no pendingOwner-style record and no "
             "acceptOwnership function. One typo'd or "
             "uncontrolled address in a single call "
             "irreversibly hands over - or bricks - control "
             "of the contract.",
      fix="Adopt the Ownable2Step pattern: transferOwnership "
          "only records a pending owner, and ownership "
          "changes only when the pending owner calls "
          "acceptOwnership."),
    S("default_admin_grant_exposed", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="DEFAULT_ADMIN_ROLE granted unsafely: the "
             "all-powerful default admin role is granted to "
             "a hardcoded literal address, or granted inside "
             "an initialize-style function where the grant "
             "rides on initialization ordering / re-"
             "initialization risk, instead of being granted "
             "only to msg.sender in the constructor. Whoever "
             "controls that literal address - or reaches the "
             "initializer first - holds every role-admin "
             "power in the system.",
      fix="Grant DEFAULT_ADMIN_ROLE only to msg.sender in "
          "the constructor (or to a named multisig / "
          "timelock passed as a constructor argument), and "
          "never to a hardcoded literal or from an "
          "initialize-style function."),
    S("renounce_role_last_admin", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="renounceRole with no last-holder guard: the "
             "renounceRole definition / override performs "
             "no remaining-holder check (no "
             "getRoleMemberCount, no hasRole guard on "
             "another holder), so the sole holder of a "
             "critical role - including DEFAULT_ADMIN_ROLE - "
             "can renounce it and leave the contract with no "
             "backup authority able to administer roles.",
      fix="Guard renouncement of critical roles: require "
          "another holder remains (getRoleMemberCount(role) "
          "> 1 or an explicit successor check) before "
          "allowing the last holder to renounce."),
    S("pause_coverage_missing", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Pause machinery does not cover a value-moving "
             "function: the contract has pause / Pausable "
             "machinery, but this public / external function "
             "moves value (transfer / withdraw / mint / burn "
             "/ redeem / claim shape) with no whenNotPaused, "
             "_requireNotPaused or paused-condition guard. "
             "During an incident the emergency pause will "
             "not stop this operation.",
      fix="Apply whenNotPaused (or the contract's paused "
          "check) to every value-moving function the pause "
          "is meant to stop, and audit coverage whenever a "
          "new value path is added."),
    S("signature_nonce_unconsumed", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Signature nonce read but never consumed: a "
             "nonce state variable / mapping is read inside "
             "a signed-digest / verify path (ecrecover or "
             "ECDSA.recover present), yet the nonce is never "
             "written, incremented or assigned anywhere in "
             "the contract. The digest therefore stays valid "
             "forever and the same signature can be replayed "
             "unboundedly - the nonce is decoration, not a "
             "replay guard.",
      fix="Consume the nonce in the verify path: increment "
          "(or otherwise advance / mark used) the signer's "
          "nonce as part of every successful verification, "
          "before the authorized action runs."),
    S("multisig_threshold_setter_unsafe", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Multisig threshold setter ungated or "
             "unbounded: a function assigns the threshold / "
             "required / numConfirmations variable on a "
             "multisig-shaped contract without a caller gate, "
             "or without any require bounding the new value "
             "to 0 < v <= owners count. A threshold of 0 "
             "turns execution into a no-signature operation; "
             "a threshold above the owner count permanently "
             "bricks the wallet.",
      fix="Gate the setter to the multisig itself / owners "
          "and bound it in the setter body: require(0 < v "
          "&& v <= owners.length) (the owner count at call "
          "time) before assigning."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirror batch 4)
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


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
        i += 1
    return text[open_pos + 1:], len(text) - 1


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (mirror of batch 4)."""
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


def _conditions(text: str) -> List[str]:
    """Contents of every require(...) / assert(...) / if(...)
    condition in the text (balanced-paren extraction)."""
    out: List[str] = []
    for m in re.finditer(r"\b(?:require|assert|if)\s*\(", text):
        inner, _ = _balanced(text, m.end() - 1)
        out.append(inner)
    return out


def _param_names(fn: Dict[str, Any]) -> List[str]:
    """Parameter names declared in a function signature."""
    sig = fn["signature"]
    i = sig.find("(")
    if i < 0:
        return []
    inner, _ = _balanced(sig, i)
    names: List[str] = []
    depth = 0
    parts: List[str] = []
    cur = ""
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    for part in parts:
        toks = [t for t in part.split()
                if t not in ("memory", "calldata", "storage",
                             "payable")]
        if len(toks) >= 2:
            names.append(toks[-1].lstrip("*"))
    return names


def _is_publicish(fn: Dict[str, Any]) -> bool:
    sig = fn["signature"]
    if re.search(r"\b(internal|private)\b", sig):
        return False
    return True


# ---------------------------------------------------------------------------
# 1. erc20_missing_return_guard
# ---------------------------------------------------------------------------

_SAFE_ERC20_RE = re.compile(
    r"SafeERC20|safeTransfer|safeApprove|safeTransferFrom|"
    r"safeIncreaseAllowance|safeDecreaseAllowance")
_TOKEN_CALL_RE = re.compile(
    r"\.\s*(?:transferFrom|transfer|approve)\s*\(")


def _analyze_missing_return(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    out: List[Dict[str, Any]] = []
    # (a) bool-expecting wrapper call, no SafeERC20 anywhere.
    if not _SAFE_ERC20_RE.search(text_all):
        for fn in fns:
            text = fn["text"]
            wrapped = None
            for cond in _conditions(text):
                if _TOKEN_CALL_RE.search(cond):
                    wrapped = cond
                    break
            if wrapped is None:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' wraps a token "
                f"call directly in a boolean condition "
                f"({wrapped.strip()[:80]}...) and the "
                f"contract never uses SafeERC20.")
            item = _hit(
                spec, fn["name"], cc._snip(text), detail,
                "token call consumed as a bool in a require / "
                "assert / if condition; no SafeERC20 usage "
                "anywhere in the contract")
            out.append(_finish_recipient(spec, item, text))
    # (b) token-shaped contract whose own transfer /
    # transferFrom declares no return value.
    if (re.search(r"\bbalanceOf\b", text_all)
            and re.search(r"\btotalSupply\b", text_all)):
        for fn in fns:
            if fn["name"] not in ("transfer", "transferFrom"):
                continue
            if "returns" in fn["signature"]:
                continue
            detail = spec.detail + (
                f" Observed: token-shaped contract's own "
                f"'{fn['name']}' signature declares no "
                f"returns clause.")
            item = _hit(
                spec, fn["name"], cc._snip(fn["text"]), detail,
                "token implementation function has no "
                "returns clause; bool-expecting callers "
                "revert against it")
            out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 2. erc721_mint_without_receiver_check
# ---------------------------------------------------------------------------

_MINT_CALL_RE = re.compile(r"\b_mint\s*\(\s*([A-Za-z_]\w*)")


def _analyze_721_mint(src: str, spec: DetectorSpec,
                      compiler: str = "",
                      contract_name: str = ""
                      ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if "ERC721" not in text_all or "_mint" not in text_all:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if "mint" not in fn["name"].lower():
            continue
        if not _is_publicish(fn):
            continue
        text = fn["text"]
        if "_safeMint" in text or "onERC721Received" in text:
            continue
        m = _MINT_CALL_RE.search(text)
        if not m:
            continue
        if m.group(1) not in _param_names(fn):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' calls "
            f"_mint({m.group(1)}, ...) with a caller-"
            f"supplied recipient and no _safeMint / "
            f"onERC721Received check on the path.")
        item = _hit(
            spec, fn["name"], cc._snip(text), detail,
            "mint path uses plain _mint to a parameter "
            "recipient; no receiver check anywhere in the "
            "mint function")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. erc1155_batch_receiver_missing
# ---------------------------------------------------------------------------

def _analyze_1155_batch(src: str, spec: DetectorSpec,
                        compiler: str = "",
                        contract_name: str = ""
                        ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    single = [fn for fn in fns
              if fn["name"] == "onERC1155Received"]
    if not single:
        return []
    if "onERC1155BatchReceived" in text_all:
        return []
    fn = single[0]
    detail = spec.detail + (
        " Observed: 'onERC1155Received' is defined but "
        "'onERC1155BatchReceived' appears nowhere in the "
        "contract.")
    item = _hit(
        spec, fn["name"], cc._snip(fn["text"]), detail,
        "single-transfer receiver hook present, batch "
        "receiver hook absent from the whole contract")
    return [_finish_recipient(spec, item, fn["text"])]


# ---------------------------------------------------------------------------
# 4. eip712_separator_unbound
# ---------------------------------------------------------------------------

_SEP_USE_RE = re.compile(
    r"\b\w*[Dd]omainSeparator\w*\b|DOMAIN_SEPARATOR|"
    r"EIP712Domain")
_SEP_NAME_RE = re.compile(
    r"\b(\w*(?:[Dd]omain_?[Ss]eparator|DOMAIN_SEPARATOR)\w*)\b")
_VERIFYISH_RE = re.compile(
    r"ecrecover|ECDSA|recover\s*\(|permit|verify|signature",
    re.I)


def _analyze_separator(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = ""
                       ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if not _SEP_USE_RE.search(text_all):
        return []
    # SILENT: some non-constructor function recomputes a
    # separator from block.chainid at call time.
    for fn in fns:
        if fn["name"] == "constructor":
            continue
        if "block.chainid" in fn["text"] and _SEP_USE_RE.search(
                fn["text"]):
            return []
    # Is the separator cached / unbound? Cached = assigned in
    # the constructor, declared immutable, or never assigned
    # inside any function body (a plain state var set once).
    # Unbound = constructed inside a function with no
    # block.chainid in that function.
    sep_vars = sorted(set(_SEP_NAME_RE.findall(text_all)))
    cached = False
    constructed_unbound = False
    for var in sep_vars:
        if re.search(r"immutable\s+(?:\w+\s+)*" + re.escape(var)
                     + r"\b", text_all):
            cached = True
        assign_re = re.compile(
            r"\b" + re.escape(var) + r"\s*=[^=]")
        for fn in fns:
            if assign_re.search(fn["text"]):
                if fn["name"] == "constructor":
                    cached = True
                elif "block.chainid" not in fn["text"]:
                    constructed_unbound = True
        if not any(assign_re.search(fn["text"]) for fn in fns):
            cached = True  # declared, never assigned in a fn
    inline_unbound = False
    for fn in fns:
        if fn["name"] == "constructor":
            continue
        if "EIP712Domain" in fn["text"] and \
                "block.chainid" not in fn["text"]:
            inline_unbound = True
    if not (cached or constructed_unbound or inline_unbound):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] == "constructor":
            continue
        if not _SEP_USE_RE.search(fn["text"]):
            continue
        if not _VERIFYISH_RE.search(fn["text"] + fn["name"]):
            continue
        why = ("cached at deployment and never recomputed "
               "from block.chainid" if cached else
               "constructed with no chainId term")
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies against a "
            f"domain separator that is {why}.")
        item = _hit(
            spec, fn["name"], cc._snip(fn["text"]), detail,
            "no function recomputes the separator from "
            "block.chainid at call time; the separator the "
            "verify path uses is fixed / chain-unbound")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 5. erc2771_msg_sender_unbound
# ---------------------------------------------------------------------------

_FORWARDER_RE = re.compile(
    r"isTrustedForwarder|trustedForwarder|_trustedForwarder|"
    r"TrustedForwarder")
_SUFFIX_RE = re.compile(
    r"msg\.data\.length\s*-\s*20|msg\.data\.length\s*>=\s*20|"
    r"calldata\b.*\b20\b|shr\s*\(|suffix", re.I)


def _analyze_2771(src: str, spec: DetectorSpec,
                  compiler: str = "",
                  contract_name: str = ""
                  ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if not _FORWARDER_RE.search(text_all):
        return []
    override = None
    anchor = None
    for fn in fns:
        if fn["name"] == "_msgSender":
            override = fn
        if anchor is None and _FORWARDER_RE.search(fn["text"]):
            anchor = fn
    if override is not None:
        body = override["text"]
        if _FORWARDER_RE.search(body) and _SUFFIX_RE.search(body):
            return []  # ERC2771Context pattern present
        target = override
        why = ("the _msgSender() override never extracts "
               "the calldata-suffix sender under the trusted "
               "forwarder")
    else:
        target = anchor or (fns[0] if fns else None)
        why = ("no _msgSender() override exists at all, so "
               "the effective sender is always raw msg.sender")
        if target is None:
            return []
    detail = spec.detail + f" Observed: {why}."
    item = _hit(
        spec, target["name"], cc._snip(target["text"]), detail,
        "trusted forwarder is referenced but the sender "
        "extraction pattern (forwarder check + 20-byte "
        "calldata suffix) is absent")
    return [_finish_recipient(spec, item, target["text"])]


# ---------------------------------------------------------------------------
# 6. eip1271_magic_value_unchecked
# ---------------------------------------------------------------------------

_ISVALIDSIG_RE = re.compile(r"\.isValidSignature\s*\(")
_MAGIC_RE = re.compile(
    r"0x1626ba7e|MAGIC|magicValue|IERC1271")


def _analyze_1271(src: str, spec: DetectorSpec,
                  compiler: str = "",
                  contract_name: str = ""
                  ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if not _ISVALIDSIG_RE.search(text):
            continue
        if _MAGIC_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' calls "
            f"isValidSignature(...) and uses the result "
            f"with no magic-value comparison in the same "
            f"function.")
        item = _hit(
            spec, fn["name"], cc._snip(text), detail,
            "isValidSignature result consumed with no "
            "comparison to 0x1626ba7e / an IERC1271 magic "
            "constant in this function")
        out.append(_finish_recipient(spec, item, text))
    return out



# ---------------------------------------------------------------------------
# 7. two_step_ownership_missing
# ---------------------------------------------------------------------------

_PENDING_OWNER_RE = re.compile(r"\b\w*[Pp]ending\w*[Oo]wner\w*\b")


def _analyze_two_step(src: str, spec: DetectorSpec,
                      compiler: str = "",
                      contract_name: str = ""
                      ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if _PENDING_OWNER_RE.search(text_all):
        return []
    if any(fn["name"] == "acceptOwnership" for fn in fns):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] != "transferOwnership":
            continue
        m = re.search(r"\b(_?owner)\s*=[^=]", fn["text"], re.I)
        if not m:
            continue
        detail = spec.detail + (
            " Observed: 'transferOwnership' assigns "
            f"{m.group(1)} directly and no pending-owner "
            "record or acceptOwnership exists anywhere in "
            "the contract.")
        item = _hit(
            spec, fn["name"], cc._snip(fn["text"]), detail,
            "direct owner assignment in transferOwnership; "
            "no pendingOwner state and no acceptOwnership "
            "function in the contract")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 8. default_admin_grant_exposed
# ---------------------------------------------------------------------------

_GRANT_ADMIN_RE = re.compile(
    r"(?:grantRole|_grantRole|_setupRole)\s*\(\s*"
    r"DEFAULT_ADMIN_ROLE\s*,\s*([^,\)]+)")
_LITERAL_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_INIT_NAME_RE = re.compile(r"^(initialize|init|setup)\w*$", re.I)


def _analyze_admin_grant(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        for m in _GRANT_ADMIN_RE.finditer(fn["text"]):
            arg = m.group(1).strip()
            literal = bool(_LITERAL_ADDR_RE.match(arg))
            in_init = bool(_INIT_NAME_RE.match(fn["name"]))
            if not (literal or in_init):
                continue  # constructor -> msg.sender is clean
            why = (f"granted to the hardcoded literal "
                   f"address {arg}" if literal else
                   f"granted inside the initialize-style "
                   f"function '{fn['name']}'")
            detail = spec.detail + f" Observed: {why}."
            item = _hit(
                spec, fn["name"], cc._snip(fn["text"]), detail,
                "DEFAULT_ADMIN_ROLE grant target / location "
                "is exposed: literal address or initialize-"
                "style function (not constructor msg.sender)")
            out.append(_finish_recipient(spec, item, fn["text"]))
            break  # one finding per granting function
    return out


# ---------------------------------------------------------------------------
# 9. renounce_role_last_admin
# ---------------------------------------------------------------------------

def _analyze_renounce(src: str, spec: DetectorSpec,
                      compiler: str = "",
                      contract_name: str = ""
                      ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if "getRoleMemberCount" in text_all:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] != "renounceRole":
            continue
        text = fn["text"]
        guarded = any("hasRole" in cond
                      for cond in _conditions(text))
        if guarded:
            continue
        # A renounce that only reverts is disabled, not a
        # last-admin hole.
        body = text.split("{", 1)[1] if "{" in text else ""
        if "revert" in body and "renounce" not in body.replace(
                fn["name"], "", 1):
            continue
        detail = spec.detail + (
            " Observed: this 'renounceRole' performs no "
            "getRoleMemberCount / hasRole remaining-holder "
            "check in its body, and none exists anywhere in "
            "the contract.")
        item = _hit(
            spec, fn["name"], cc._snip(text), detail,
            "renounceRole body has no remaining-holder "
            "check; no getRoleMemberCount anywhere in the "
            "contract")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 10. pause_coverage_missing
# ---------------------------------------------------------------------------

_PAUSE_MACHINERY_RE = re.compile(
    r"Pausable|_pause\s*\(|function\s+pause\s*\(|whenPaused")
_VALUE_NAME_RE = re.compile(
    r"transfer|withdraw|mint|burn|redeem|claim", re.I)
_VALUE_BODY_RE = re.compile(
    r"\.transfer\s*\(|\.call\s*\{\s*value|safeTransfer|"
    r"_mint\s*\(|_burn\s*\(|\.send\s*\(")
_PAUSE_GUARD_SIG_RE = re.compile(r"whenNotPaused")
_PAUSE_GUARD_BODY_RE = re.compile(
    r"_requireNotPaused|require\s*\(\s*!?\s*paused|"
    r"if\s*\(\s*!?\s*paused|whenNotPaused")


def _analyze_pause_coverage(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if not _PAUSE_MACHINERY_RE.search(text_all):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        name = fn["name"]
        if name in ("constructor", "pause", "unpause", ""):
            continue
        if not _is_publicish(fn):
            continue
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        if not (_VALUE_NAME_RE.search(name)
                or _VALUE_BODY_RE.search(text)):
            continue
        if _PAUSE_GUARD_SIG_RE.search(fn["signature"]) or \
                _PAUSE_GUARD_BODY_RE.search(text):
            continue
        detail = spec.detail + (
            f" Observed: '{name}' moves value with no "
            f"pause guard while the contract carries pause "
            f"machinery.")
        item = _hit(
            spec, name, cc._snip(text), detail,
            "value-moving function has no whenNotPaused / "
            "_requireNotPaused / paused-condition guard "
            "although pause machinery exists in the "
            "contract")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 11. signature_nonce_unconsumed
# ---------------------------------------------------------------------------

_NONCE_IDENT_RE = re.compile(r"\b\w*[Nn]once\w*\b")
_RECOVER_RE = re.compile(r"ecrecover|ECDSA\.recover|recover\s*\(")


def _nonce_written(var: str, text_all: str) -> bool:
    v = re.escape(var)
    return bool(
        re.search(r"\b" + v + r"\s*(\[[^\]]*\])?\s*"
                  r"(\+\+|--|\+=|-=|=[^=])", text_all)
        or re.search(r"\+\+\s*" + v + r"\b", text_all)
        or re.search(r"\bdelete\s+" + v + r"\b", text_all))


def _analyze_nonce_unconsumed(src: str, spec: DetectorSpec,
                              compiler: str = "",
                              contract_name: str = ""
                              ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if not _RECOVER_RE.search(text):
            continue
        read_vars = sorted(set(_NONCE_IDENT_RE.findall(text)))
        unconsumed = [v for v in read_vars
                      if not _nonce_written(v, text_all)]
        if not unconsumed:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' reads nonce "
            f"identifier(s) {unconsumed} in its signed-"
            f"digest / verify path, and no write, increment "
            f"or assignment to them exists anywhere in the "
            f"contract.")
        item = _hit(
            spec, fn["name"], cc._snip(text), detail,
            "nonce is read in the verify path but never "
            "written anywhere in the contract (read-vs-write "
            "scan over the whole scoped source)")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 12. multisig_threshold_setter_unsafe
# ---------------------------------------------------------------------------

_THRESHOLD_VAR_RE = re.compile(
    r"\b(\w*(?:[Tt]hreshold|[Rr]equired|"
    r"numConfirmations)\w*)\s*=[^=]")
_MULTISIG_SHAPE_RE = re.compile(
    r"address\[\]\s+(?:public\s+|private\s+|internal\s+)?"
    r"\w*[Oo]wner|mapping\s*\([^)]*\)\s+(?:public\s+)?isOwner")
_BOUND_RE = re.compile(
    r">\s*0|<\s*\w*[Oo]wner|owner", re.I)


def _analyze_threshold_setter(src: str, spec: DetectorSpec,
                              compiler: str = "",
                              contract_name: str = ""
                              ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    if not _MULTISIG_SHAPE_RE.search(text_all):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] == "constructor":
            continue
        text = fn["text"]
        m = _THRESHOLD_VAR_RE.search(text)
        if not m:
            continue
        var = m.group(1)
        gated = _caller_gated(fn, scope)
        # The bound may be written against the assigned
        # parameter (threshold = newThreshold) rather than
        # the state var itself - check conditions against
        # both names.
        rhs = re.search(r"\b" + re.escape(var)
                        + r"\s*=\s*([A-Za-z_]\w*)", text)
        check_vars = [var] + ([rhs.group(1)] if rhs else [])
        conds = _conditions(text)

        def _mentions(cond: str) -> bool:
            return any(re.search(
                r"\b" + re.escape(v) + r"\b", cond)
                for v in check_vars)

        bounded = False
        for cond in conds:
            if _mentions(cond) and ">" in cond and "<" in cond:
                bounded = True
            if _mentions(cond) and re.search(r">\s*0", cond) \
                    and re.search(
                        r"<=\s*[\w.]*([Oo]wner|ownerCount)",
                        cond):
                bounded = True
        # A bound may span two conditions: v > 0 in one
        # require and v <= owners in another.
        if not bounded:
            has_low = any(
                _mentions(c)
                and re.search(r">\s*0|0\s*<", c)
                for c in conds)
            has_high = any(
                _mentions(c)
                and re.search(r"<=", c)
                and re.search(r"[Oo]wner", c)
                for c in conds)
            bounded = has_low and has_high
        if gated and bounded:
            continue
        why = []
        if not gated:
            why.append("ungated (no only* modifier, "
                       "msg.sender identity check or role "
                       "check)")
        if not bounded:
            why.append("unbounded (no require bounding the "
                       "value to 0 < v <= owners count)")
        detail = spec.detail + (
            f" Observed: '{fn['name']}' assigns {var} and "
            f"is " + " and ".join(why) + ".")
        item = _hit(
            spec, fn["name"], cc._snip(text), detail,
            "threshold setter gate/bounds analysis: "
            + "; ".join(why))
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "erc20_missing_return_guard": _analyze_missing_return,
    "erc721_mint_without_receiver_check": _analyze_721_mint,
    "erc1155_batch_receiver_missing": _analyze_1155_batch,
    "eip712_separator_unbound": _analyze_separator,
    "erc2771_msg_sender_unbound": _analyze_2771,
    "eip1271_magic_value_unchecked": _analyze_1271,
    "two_step_ownership_missing": _analyze_two_step,
    "default_admin_grant_exposed": _analyze_admin_grant,
    "renounce_role_last_admin": _analyze_renounce,
    "pause_coverage_missing": _analyze_pause_coverage,
    "signature_nonce_unconsumed": _analyze_nonce_unconsumed,
    "multisig_threshold_setter_unsafe":
        _analyze_threshold_setter,
}


def analyze_deep5_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-5 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)



# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-3 collection / fetch /
# proxy resolution; analysis is analyze_deep5_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit5Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 5)"
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
        for item in analyze_deep5_source(
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
                source="deep audit detector batch 5 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit5Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 5) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
