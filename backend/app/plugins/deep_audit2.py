"""Deep-audit detectors, batch 2: AI plugin dev (2026-11-03).

Six more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-1 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- hook_cei_reentrancy: ERC-777 / ERC-1363 callback-hook CEI
  ordering. The token invokes the recipient/sender HOOK
  (tokensReceived / tokensToSend / onTransferReceived /
  onTokenTransfer through an interface cast) BEFORE it writes
  the accounting state the hook can reenter against, with no
  reentrancy guard. Narrower than contract_logic's generic CEI
  reentrancy, which fires on ANY external call before a write:
  this one requires the callback-hook call site and an
  accounting variable whose FIRST write lands after the hook.
- bridge_replay_unbound_digest: a bridge executor that DOES
  verify its message (ecrecover / validator / Merkle check
  present - the shape bridge_message_payload_injection stays
  silent on, since it requires verification to be ABSENT) but
  the verified digest binds too little: it omits the source
  chain id and/or the origin sender and/or a nonce, so a
  message proven on one chain (or by one sender, or once) is
  replayable on another chain / for another sender / again.
- eip7702_unverified_delegate: EIP-7702 delegated-account
  hygiene. A delegation setter (or the on-chain 0xef0100
  designator itself, the bytecode-aware lane) points an
  account at a delegate with NO verification at all: no
  allowlist, no code check, no signed authorization. A
  caller-supplied unverified delegate is a candidate (whoever
  sets it owns the account's execution); a fixed unverified
  delegate is trigger-only (the power sits with one fixed
  address). Sponsored-init replay is covered as the sibling
  shape: an init entry point on a 7702-aware account with no
  initialized flag and no gate can be re-run by anyone.
- l2_sequencer_uptime_missing: Chainlink price reads on an L2
  with NO sequencer uptime feed check. Disjoint from
  system_stale_oracle_data, which fires only when the price
  freshness fields are never read at all: this detector fires
  even when updatedAt IS checked, because after a sequencer
  outage the price feed itself is stale in a way the price
  feed's own timestamps cannot reveal - only the sequencer
  uptime feed (answer + startedAt + grace period) can.
- fee_on_transfer_overcredit: receiving-side deposit
  accounting. A vault / lending / staking deposit pulls tokens
  with transferFrom and credits the NOMINAL amount parameter
  (shares / balance keyed on the depositor) without ever
  measuring the balance delta, so a fee-on-transfer token
  (or any token that delivers less than asked) is credited at
  face value and the shortfall is socialized to the pool -
  the depositor redeems against other depositors' funds.
- create2_metamorphic_redeploy: CREATE2 + selfdestruct in the
  same compilation. Code living at a fixed, pre-computed
  address can be destroyed and replaced with DIFFERENT code
  at the SAME address, so any trust pinned to that address
  (allowlists, integrations, approvals) silently survives a
  total code swap. Disjoint from
  proxy_deterministic_deployment_collision, which is about
  salt squatting / pre-computation and needs no selfdestruct;
  this one needs the destroy leg.

Detection only: verified-source / bytecode static analysis in
the fast lane, never sends a transaction, never calls the
contract for value. Fetch failure is reported honestly by the
shared scaffolding (analyzed 0 / no verified source - skipped),
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
FAMILY = "deep2"

SPECS = [
    S("hook_cei_reentrancy", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Callback-hook CEI violation (ERC-777 / ERC-1363): "
             "the transfer path invokes the token callback hook "
             "on the counterparty BEFORE updating the accounting "
             "state, and carries no reentrancy guard. During the "
             "hook the balances still show the pre-transfer "
             "state, so a malicious receiver (or sender, via "
             "tokensToSend) reenters and spends the same balance "
             "again - the ERC-777 / imBTC / Lendf.me shape. "
             "Generic CEI detectors flag any call-before-write; "
             "this one fires only on the hook call site with an "
             "accounting variable first written after the hook.",
      fix="Update all accounting state before invoking the "
          "hook (checks-effects-interactions), or hold a "
          "reentrancy lock across the hook call."),
    S("bridge_replay_unbound_digest", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Bridge message replay (unbound digest): the "
             "executor verifies a signature / proof over a "
             "message digest that does not bind the full "
             "message identity - the source chain id, the "
             "origin sender and/or a nonce is missing from the "
             "hashed inputs - so the same proven message can be "
             "replayed on another chain, attributed to another "
             "sender, or executed again wherever the executed "
             "marker is keyed on the same under-bound digest. "
             "Verification being present is exactly what keeps "
             "generic payload-injection detectors silent here.",
      fix="Hash the full message identity into the verified "
          "digest: source chain id, origin sender, nonce / "
          "message id, destination chain, recipient and amount, "
          "and consume a per-message nonce on execution."),
    S("eip7702_unverified_delegate", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="EIP-7702 unverified delegation: an account's "
             "delegation designator (0xef0100 || delegate) is set "
             "to a delegate with no verification at all - no "
             "allowlist, no code check on the delegate, no "
             "signed authorization binding the choice. Whoever "
             "controls the delegate contract controls the "
             "account's execution, so an unverified delegate is "
             "an account-takeover surface; where the delegate is "
             "caller-supplied anyone who can call the setter "
             "owns the account.",
      fix="Bind delegation changes to the account owner's "
          "signed authorization, allowlist audited delegates, "
          "and require the delegate to have code (and pinned, "
          "verified source) before pointing an account at it."),
    S("l2_sequencer_uptime_missing", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="L2 sequencer-uptime staleness: a Chainlink price "
             "feed is consumed on an L2 with no sequencer "
             "uptime feed check anywhere in the compilation. "
             "When the sequencer is down (or has just come "
             "back), transactions queue and the price feed "
             "settles on pre-outage data; checking the price "
             "feed's own updatedAt cannot detect this, because "
             "the feed could not update either. The Chainlink "
             "L2 pattern requires reading the sequencer uptime "
             "feed, requiring answer == 0, and waiting out a "
             "grace period after the sequencer restarts before "
             "trusting prices.",
      fix="Read the L2 sequencer uptime feed before trusting "
          "any price: require its answer to be 0 (sequencer "
          "up) and block.timestamp - startedAt to exceed the "
          "grace period after a restart."),
    S("fee_on_transfer_overcredit", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Fee-on-transfer deposit overcredit: the deposit "
             "path pulls tokens with transferFrom and credits "
             "the NOMINAL amount parameter as shares / balance, "
             "without measuring how much actually arrived "
             "(balanceOf before vs after). A fee-on-transfer, "
             "rebasing-down or otherwise short-delivering token "
             "is credited at face value, and the credited "
             "position redeems against the full pool - the "
             "shortfall is taken from the other depositors.",
      fix="Credit the measured balance delta: read "
          "balanceOf(address(this)) before and after the "
          "transferFrom and credit only the difference (or "
          "reject non-standard tokens at the door)."),
    S("create2_metamorphic_redeploy", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="CREATE2 metamorphic redeploy: the compilation "
             "both deploys with CREATE2 and contains a "
             "selfdestruct path, so the code at a fixed, "
             "pre-computed address can be destroyed and "
             "replaced by different code at the same address. "
             "Approvals, allowlist entries and integrations "
             "that trust the address keep trusting it after a "
             "total code swap. This is not salt squatting "
             "(the deterministic-collision class needs no "
             "selfdestruct); the destroy leg is what makes the "
             "address's code mutable.",
      fix="Do not pair CREATE2 deployment with selfdestruct: "
          "deploy immutable code (no destroy path), or treat "
          "any address whose code can change as untrusted and "
          "pin expected code hashes in consumers."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}
EIP7702_ID = "eip7702_unverified_delegate"


# ---------------------------------------------------------------------------
# Shared helpers
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
            "value or control here, classified CANDIDATE under "
            "the receive rule.")
    return item


def _finish_recipient(spec: DetectorSpec, item: Dict[str, Any],
                      fn_text: str) -> Dict[str, Any]:
    recipient, rdetail = cl.classify_recipient(fn_text)
    return _classify(item, recipient, rdetail)


_LOCK_BODY_RE = re.compile(
    r"(locked|_status|reentrancy|entered)\w*\s*=\s*"
    r"(true|2|_ENTERED|ENTERED)", re.I)


def _guard_names(scope) -> set:
    names = {"nonReentrant", "nonReentrantView"}
    for name, body in scope.modifiers.items():
        if _LOCK_BODY_RE.search(body):
            names.add(name)
    return names


def _sig_has_guard(sig: str, guards: set) -> bool:
    return any(re.search(r"\b" + re.escape(g) + r"\b", sig)
               for g in guards if g)


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


# ---------------------------------------------------------------------------
# 1. Callback-hook CEI ordering (ERC-777 / ERC-1363)
# ---------------------------------------------------------------------------

_HOOK_CALL_RE = re.compile(
    r"\.\s*(tokensReceived|tokensToSend|onTransferReceived|"
    r"onTokenTransfer)\s*\(")
_ACCOUNTING_RE = re.compile(
    r"balance|supply|shares|allowance|debt|credit|reserve|"
    r"total|stake|deposit|settled|escrow|locked", re.I)


def _analyze_hook_cei(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    guards = _guard_names(scope)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        text = fn["text"]
        m = _HOOK_CALL_RE.search(text)
        if not m:
            continue
        if _sig_has_guard(fn["signature"], guards):
            continue  # lock held across the hook: protected
        writes = cl._state_writes(text, state)
        written_before = {v for p, v in writes if p < m.start()}
        late = [v for p, v in writes
                if p > m.start() and v not in written_before
                and _ACCOUNTING_RE.search(v)]
        if not late:
            continue  # CEI respected for the hook-relevant state
        detail = spec.detail + (
            f" Observed: '{fn['name']}' invokes the "
            f"'{m.group(1)}' callback hook and only afterwards "
            f"writes the accounting state "
            f"({', '.join(sorted(set(late))[:3])}), with no "
            "reentrancy guard on the function. Gate analysis: "
            "no reentrancy lock and no pre-hook state update "
            "protects the reentry window.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated: no reentrancy guard, accounting "
                    "state written after the hook call")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. Bridge message replay (verified digest, unbound identity)
# ---------------------------------------------------------------------------

_MSG_FN_RE = re.compile(
    r"message|relay|claim|execute|process|deliver|bridge", re.I)
_VERIFY_RE = re.compile(
    r"ecrecover|MerkleProof|\.verify\s*\(|verifyProof|"
    r"validator", re.I)
_BINDINGS = (
    ("source chain id", re.compile(
        r"chainid|chainId|srcChain|sourceChain|originChain|"
        r"fromChain", re.I)),
    ("origin sender", re.compile(
        r"sender|originator|messageSender|srcSender", re.I)),
    ("nonce / message id", re.compile(
        r"nonce|messageId|sequence|msgIndex|messageIndex", re.I)),
)


def _digest_inputs(text: str) -> List[str]:
    """Argument strings of every abi.encode / encodePacked call
    that feeds a keccak256 in this function text."""
    out: List[str] = []
    for m in re.finditer(r"keccak256\s*\(", text):
        inner, _ = _balanced(text, text.index("(", m.start()))
        em = re.search(r"abi\.encode(?:Packed)?\s*\(", inner)
        if em:
            args, _ = _balanced(inner, inner.index("(", em.start()))
            out.append(args)
        else:
            out.append(inner)
    return out


def _analyze_bridge_replay(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "keccak256" not in text:
            continue
        if not _VERIFY_RE.search(text):
            continue  # no verification: payload-injection class
        if not (_MSG_FN_RE.search(fn["name"]) or
                _MSG_FN_RE.search(text)):
            continue
        inputs = _digest_inputs(text)
        if not inputs:
            continue
        joined = " ".join(inputs)
        missing = [label for label, rx in _BINDINGS
                   if not rx.search(joined)]
        # A binding enforced outside the digest still binds:
        # a require comparing the chain id, or an executed /
        # consumed marker keyed on a nonce-shaped parameter.
        if "source chain id" in missing and re.search(
                r"require\s*\([^)]*(chainid|srcChain|sourceChain)",
                text, re.I):
            missing.remove("source chain id")
        if "nonce / message id" in missing and re.search(
                r"(executed|processed|consumed|claimed)\s*\[\s*"
                r"\w*(nonce|messageId|sequence)\w*\s*\]", text,
                re.I):
            missing.remove("nonce / message id")
        if not missing:
            continue  # fully bound digest: replay-proof shape
        moves = bool(cl._state_writes(text, state)) or \
            bool(cl._external_calls(text))
        if not moves:
            continue
        gated = cl._gated_deep(fn, scope)
        gate = ("caller gate present, but it binds the "
                "submitter, not the message - the replay "
                "stands" if gated else
                "no caller gate; verification present but the "
                "digest under-binds the message identity")
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies a digest over "
            f"({joined.strip()[:120]}) which omits: "
            f"{', '.join(missing)}. Gate analysis: {gate}.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    gate)
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. EIP-7702 unverified delegate (+ bytecode designator lane)
# ---------------------------------------------------------------------------

_DELEGATE_FN_RE = re.compile(r"delegate|designator|setcode", re.I)
_VERIFY_DELEGATE_RE = re.compile(
    r"allowed|whitelist|allowlist|approved|trusted|"
    r"extcodesize|\.code\.length|isContract|ecrecover|ECDSA|"
    r"verifySignature|signedAuthorization", re.I)
_INIT_FN_RE = re.compile(
    r"^(init|initialize|sponsorInit|setup)$", re.I)


def eip7702_delegate_of(code_hex: str) -> Optional[str]:
    """The delegate address of an EIP-7702 designator account
    (code == 0xef0100 || delegate), else None."""
    if not code_hex:
        return None
    h = code_hex.lower()
    if h.startswith("0x"):
        h = h[2:]
    if h.startswith("ef0100") and len(h) >= 46:
        return "0x" + h[6:46]
    return None


def _fn_addr_params(sig: str) -> List[str]:
    i = sig.find("(")
    if i < 0:
        return []
    inner, _ = _balanced(sig, i)
    names = []
    for part in inner.split(","):
        if "address" not in part:
            continue
        toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", part)
        if toks:
            names.append(toks[-1])
    return names


def _analyze_7702(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    stripped = cc._strip_comments(src)
    has_7702_context = bool(re.search(
        r"7702|0xef0100|delegat", stripped, re.I))
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        is_setter = bool(_DELEGATE_FN_RE.search(fn["name"])) or \
            "0xef0100" in text
        if is_setter and re.search(r"=\s*[^=]", text):
            if _VERIFY_DELEGATE_RE.search(text) or \
                    _VERIFY_DELEGATE_RE.search(fn["signature"]):
                continue  # some verification binds the choice
            params = _fn_addr_params(fn["signature"])
            supplied = [p for p in params
                        if re.search(r"delegat|impl|target|code",
                                     p, re.I)]
            detail = spec.detail + (
                f" Observed: '{fn['name']}' sets the account "
                "delegation with no allowlist, code check or "
                "signed authorization in the function. Gate "
                "analysis: the delegation choice itself is "
                "unverified.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "delegation target unverified: no "
                        "allowlist, code check or signature")
            if supplied:
                out.append(_classify(
                    item, "CALLER-SUPPLIED",
                    f"delegate taken from caller parameter "
                    f"'{supplied[0]}'"))
            else:
                out.append(_classify(
                    item, "FIXED",
                    "delegate taken from stored / constant "
                    "state, not from the caller"))
            continue
        # Sponsored-init replay: init on a 7702-aware account,
        # no initialized flag written or checked, no gate.
        if has_7702_context and _INIT_FN_RE.match(fn["name"]):
            if cl._gated_deep(fn, scope):
                continue
            if re.search(r"initiali[sz]ed", text, re.I):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' is an init entry "
                "point on a delegation-aware account with no "
                "initialized flag and no gate, so it can be "
                "re-run (sponsored-init replay) after the "
                "account is delegated. Gate analysis: no gate "
                "and no one-shot flag.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "ungated init, no initialized flag")
            out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. L2 sequencer-uptime staleness
# ---------------------------------------------------------------------------

_L2_CONTEXT_RE = re.compile(
    r"arbitrum|optimism|\bscroll\b|linea|zksync|metis|"
    r"mantle|blast|42161|8453|534352|59144", re.I)
_SEQUENCER_RE = re.compile(
    r"sequencer|uptimefeed|uptime_feed|grace_period|GRACE", re.I)


def _analyze_l2_sequencer(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    if _SEQUENCER_RE.search(scope.scoped_text):
        return []  # an uptime check exists somewhere in scope
    if not _L2_CONTEXT_RE.search(scope.scoped_text):
        return []  # not identifiably an L2 deployment
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if "latestRoundData" not in fn["text"]:
            continue
        checks_price_freshness = bool(re.search(
            r"updatedAt|answeredInRound", fn["text"]))
        detail = spec.detail + (
            f" Observed: '{fn['name']}' consumes a Chainlink "
            "price feed in an L2-context compilation with no "
            "sequencer uptime feed read anywhere in scope. "
            + ("The price feed's own updatedAt IS checked, so "
               "this is not the plain stale-oracle shape - the "
               "missing piece is specifically the sequencer "
               "uptime / grace-period check."
               if checks_price_freshness else
               "No price freshness check was found either."))
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "no sequencer uptime gate anywhere in the "
                    "compilation")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 5. Fee-on-transfer deposit overcredit (receiving side)
# ---------------------------------------------------------------------------

_PULL_RE = re.compile(
    r"transferFrom\s*\(\s*msg\.sender\s*,\s*address\s*\(\s*"
    r"this\s*\)\s*,\s*([A-Za-z_][\w]*)\s*\)")
_CREDIT_MAP_RE = re.compile(
    r"([A-Za-z_][\w]*)\s*\[\s*([^\]]+?)\s*\]\s*\+=\s*"
    r"([A-Za-z_][\w]*)\s*;")
_MINT_RE = re.compile(
    r"_mint\s*\(\s*([^,]+?)\s*,\s*([A-Za-z_][\w]*)\s*\)")
_BEFORE_RE = re.compile(
    r"([A-Za-z_][\w]*)\s*=\s*[^;]*?balanceOf\s*\(\s*address"
    r"\s*\(\s*this\s*\)\s*\)")


def _delta_measured(text: str) -> bool:
    m = _BEFORE_RE.search(text)
    if not m:
        return False
    var = m.group(1)
    rest = text[m.end():]
    return bool(re.search(r"-\s*" + re.escape(var) + r"\b", rest)
                or re.search(r"balanceOf\s*\([^)]*\)\s*-\s*"
                             + re.escape(var) + r"\b", rest))


def _credit_target(text: str, amount_var: str):
    """(target_expr, kind) for a credit of the nominal amount."""
    for m in _CREDIT_MAP_RE.finditer(text):
        if m.group(3) == amount_var:
            return m.group(2).strip(), "mapping credit"
    for m in _MINT_RE.finditer(text):
        if m.group(2) == amount_var:
            return m.group(1).strip(), "_mint credit"
    return None, ""


def _analyze_fot_overcredit(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        pull = _PULL_RE.search(text)
        if not pull:
            continue
        amount_var = pull.group(1)
        params = set(_fn_addr_params(fn["signature"])) | set(
            re.findall(r"[A-Za-z_][\w]*",
                       fn["signature"]))
        if amount_var not in fn["signature"]:
            continue
        if _delta_measured(text):
            continue  # credits the measured delta: correct
        target, how = _credit_target(text, amount_var)
        if target is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' pulls "
            f"'{amount_var}' with transferFrom and credits it "
            f"at face value ({how} to {target}) with no "
            "balanceOf delta measurement anywhere in the "
            "function. Gate analysis: no delta check and no "
            "token allowlist binds what can be deposited.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no balance-delta measurement in the "
                    "deposit path")
        if target == "msg.sender":
            item = _classify(
                item, "CALLER",
                "credit keyed on msg.sender: the nominal "
                "credit is the caller's own deposit on paper, "
                "but the excess over what actually arrived is "
                "caller-received value taken from the pool")
        elif target in params:
            item = _classify(item, "CALLER-SUPPLIED",
                             f"credit target is caller "
                             f"parameter '{target}'")
        elif target in state or re.match(
                r"^(address\s*\(|0x)", target):
            item = _classify(item, "FIXED",
                             f"credit target '{target}' is "
                             "stored / hardcoded state")
        else:
            item = _finish_recipient(spec, item, text)
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 6. CREATE2 metamorphic redeploy
# ---------------------------------------------------------------------------

_CREATE2_RE = re.compile(
    r"create2\s*\(|\{\s*salt\s*:|Create2\.deploy|"
    r"new\s+[A-Za-z_][\w]*\s*\{\s*salt", re.I)
_SELFDESTRUCT_RE = re.compile(r"selfdestruct\s*\(")


def _analyze_create2_metamorphic(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    stripped = scope.scoped_text
    if not _CREATE2_RE.search(stripped):
        return []
    if not _SELFDESTRUCT_RE.search(stripped):
        return []  # immutable CREATE2 code: no redeploy leg
    deploy_fn = next(
        (fn for fn in fns if _CREATE2_RE.search(fn["text"])),
        None)
    destroy_fn = next(
        (fn for fn in fns if _SELFDESTRUCT_RE.search(fn["text"])),
        None)
    if deploy_fn is None:
        return []
    both_gated = bool(
        destroy_fn and cl._gated_deep(deploy_fn, scope)
        and cl._gated_deep(destroy_fn, scope))
    gate = ("both the deploy and destroy legs are "
            "owner-gated: the metamorphic power sits with one "
            "fixed authority" if both_gated else
            "at least one of the deploy / destroy legs is "
            "ungated")
    detail = spec.detail + (
        f" Observed: '{deploy_fn['name']}' deploys with "
        "CREATE2 and the compilation carries a selfdestruct "
        f"path ({('in ' + chr(39) + destroy_fn['name'] + chr(39)) if destroy_fn else 'in an in-scope contract'}), "
        f"so the deployed address's code is replaceable. "
        f"Gate analysis: {gate}.")
    item = _hit(spec, deploy_fn["name"],
                cc._snip(deploy_fn["text"]), detail, gate)
    if both_gated:
        item = _classify(item, "FIXED",
                         "deploy and destroy both gated to a "
                         "fixed authority")
    else:
        params = _fn_addr_params(deploy_fn["signature"])
        named = [p for p in re.findall(
            r"[A-Za-z_][\w]*", deploy_fn["signature"])
            if p not in ("function", "external", "public",
                         "returns", "payable")]
        if params or any(re.search(r"salt|bytecode|code|init",
                                   p, re.I) for p in named):
            item = _classify(item, "CALLER-SUPPLIED",
                             "deployment inputs (salt / code / "
                             "target) come from the caller")
        else:
            item = _classify(item, "CALLER",
                             "any caller can drive the "
                             "deploy/destroy cycle")
    return [item]


ANALYZERS = {
    "hook_cei_reentrancy": _analyze_hook_cei,
    "bridge_replay_unbound_digest": _analyze_bridge_replay,
    "eip7702_unverified_delegate": _analyze_7702,
    "l2_sequencer_uptime_missing": _analyze_l2_sequencer,
    "fee_on_transfer_overcredit": _analyze_fot_overcredit,
    "create2_metamorphic_redeploy": _analyze_create2_metamorphic,
}


def analyze_deep2_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-2 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-1 collection / fetch /
# proxy resolution; analysis is analyze_deep2_source per spec,
# plus the bytecode-aware EIP-7702 designator lane)
# ---------------------------------------------------------------------------

class DeepAudit2Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 2)"
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
        if self._spec is not None and \
                self._spec.id == EIP7702_ID:
            got = await self._bytecode_7702(
                ctx, key, chain, addr, code_hex, findings) or got
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

    async def _bytecode_7702(self, ctx: Ctx, key: Optional[str],
                             chain: cc.ChainConfig, addr: str,
                             code_hex: str,
                             findings: List[Finding]) -> bool:
        """Bytecode-aware lane: the target's own code IS an
        EIP-7702 designator. The delegate it points at is the
        account's code now; if that delegate has no verified
        source - or its source shows it can be re-pointed /
        destroyed - the account runs unverifiable code."""
        spec = self._spec
        delegate = eip7702_delegate_of(code_hex or "")
        if spec is None or not delegate:
            return False
        dsrc = None
        try:
            dsrc = await cc.fetch_verified_source(
                ctx, chain, delegate, key)
        except Exception:
            dsrc = None
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id,
                   "contract_role": "eip7702_account",
                   "delegate_address": delegate,
                   "bytecode_only": True}
        if not dsrc:
            detail = (
                spec.detail + (
                    f" Observed on-chain: the account at {addr} "
                    f"carries the EIP-7702 designator 0xef0100 "
                    f"pointing at delegate {delegate}, which has "
                    "NO verified source - the code this account "
                    "now executes cannot be audited. Recipient "
                    "analysis: the delegate is a FIXED address "
                    "holding the account's execution power - "
                    "TRIGGER-ONLY under the receive rule."))
            ev = dict(base_ev)
            ev.update({
                "severity": "low", "check": spec.id,
                "detector_outcome": spec.outcome,
                "function": "",
                "code": (code_hex or "")[:66],
                "detail": detail,
                "recipient": "FIXED",
                "report_class": "trigger_only",
                "gate_analysis": "delegate has no verified "
                                 "source to audit",
                "remediation": spec.fix})
            findings.append(self._f(
                "web3", spec.id,
                f"LOW: {spec.label}: EIP-7702 account {addr} on "
                f"{chain.name} delegates to unverified "
                f"{delegate}\n\n{detail}",
                source="deep audit detector (bytecode)",
                source_url=url, confidence=55, passive=True,
                evidence=ev))
            return True
        dtext = dsrc.get("source", "") or ""
        if re.search(r"selfdestruct\s*\(|\.delegatecall\s*\(|"
                     r"delegate", dtext, re.I) and \
                re.search(r"selfdestruct\s*\(|"
                          r"\.delegatecall\s*\(", dtext):
            detail = (
                spec.detail + (
                    f" Observed on-chain: the account at {addr} "
                    f"delegates (0xef0100) to {delegate}, whose "
                    "verified source carries a selfdestruct / "
                    "delegatecall surface - the code behind this "
                    "account can be destroyed or re-pointed. "
                    "Recipient analysis: the delegate is a FIXED "
                    "address - TRIGGER-ONLY under the receive "
                    "rule."))
            ev = dict(base_ev)
            ev.update({
                "severity": "low", "check": spec.id,
                "detector_outcome": spec.outcome,
                "function": "",
                "code": (code_hex or "")[:66],
                "detail": detail,
                "recipient": "FIXED",
                "report_class": "trigger_only",
                "gate_analysis": "delegate source is "
                                 "destroyable / re-pointable",
                "bytecode_only": False,
                "remediation": spec.fix})
            findings.append(self._f(
                "web3", spec.id,
                f"LOW: {spec.label}: EIP-7702 account {addr} on "
                f"{chain.name} delegates to destroyable "
                f"{delegate}\n\n{detail}",
                source="deep audit detector (bytecode)",
                source_url=url, confidence=55, passive=True,
                evidence=ev))
            return True
        return False

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
        for item in analyze_deep2_source(
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
                source="deep audit detector batch 2 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit2Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 2) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            "verified-source analysis, fast lane, detection "
            "only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
