"""Deep-audit detectors, batch 7: bridge + proxy slices (2026-11-04).

Twelve chain-agnostic EVM detectors built from the coverage-c
audit (BRG / PRX concepts), each taking the slice the existing
registry leaves uncovered and staying disjoint from its
neighbours (in particular batch 4's two bridge detectors):

- bridge_digest_no_destination_chain (BRG-001 slice): a bridge
  digest binds source chain / origin sender / nonce but omits
  the DESTINATION chain entirely (and carries no generic
  chain-id term), so a message proven on one destination can
  be replayed on another. Disjoint from
  bridge_replay_unbound_digest, which owns digests missing a
  source / sender / nonce binding - a digest with NO binding
  terms at all stays silent here.
- bridge_bytes_proof_length_unvalidated (BRG-002 slice): the
  bytes / bytes[] proof-blob lane batch 4 does not reach (it
  owns bytes32[]): a verify / claim / receive path passes a
  bytes proof to a verifier with NO condition anywhere in the
  contract inspecting that proof's .length.
- bridge_static_gas_limit (BRG-003 slice): a cross-chain
  dispatch whose gas limit is a numeric literal, a constant,
  or a state variable with a literal initializer, carried via
  a gasLimit: / gas: struct field or {gas: } call option.
  Caller-supplied or computed gas stays silent. Low severity:
  a static limit is a liveness / griefing risk, not a drain.
- bridge_receiver_sender_unchecked (BRG-004 slice): a
  cross-chain receive / execute handler that DOES perform
  verification or state execution but never compares
  msg.sender to anything - the slice the no-verification
  payload-injection detectors cannot see.
- bridge_mint_burn_gate_asymmetry (BRG-005 slice): one
  contract holds both a mint-side and a burn-side bridge
  function and their caller-gate classes differ; the finding
  lands on the ungated side.
- bridge_nonce_order_unenforced (BRG-010 slice): a bridge
  receive path stores an incoming nonce while the contract
  keeps a sequential counter (nextNonce / expectedNonce /
  lastNonce / inboundNonce) that NO condition anywhere
  compares the incoming nonce against, so messages can
  execute out of order.
- bridge_proof_nullifier_missing (BRG-006): a ZK / proof
  verifier's success gates a mint / release / transfer and
  the path records NOTHING keyed by the proof or its public
  inputs - no nullifier, spent, used-proof or processed
  marker - so the same proof can be submitted repeatedly.
- bridge_payload_slice_unbounded (BRG-007 slice): a message
  handler indexes, slices or assembly-reads a bytes payload
  with NO length condition in the function. abi.decode-only
  handlers are the safe shape and stay silent.
- uups_authorize_upgrade_missing (PRX-002 slice): in a UUPS
  context, an _authorizeUpgrade override with an EMPTY body
  (high), or UUPSUpgradeable inheritance with no
  _authorizeUpgrade definition anywhere in the source
  (also high; the finding detail carries the flattened-source
  caveat - the definition may live in an unflattened parent).
- initializer_flag_after_call (PRX-007 slice): an init-named
  function WITHOUT an initializer modifier whose hand-rolled
  initialized flag is assigned only AFTER the first external
  call, leaving a re-entry window during initialization.
- diamond_selector_collision (PRX-008): a bundle with diamond
  markers (diamondCut / IDiamondCut / facets()) where two
  DISTINCT non-diamond contracts declare functions with
  identical normalized signatures (name + parameter types),
  so one facet shadows the other's selector.
- beacon_implementation_zero_accepted (PRX-009): a beacon-
  context setter assigns an address parameter to beacon /
  implementation storage with NO zero-address condition on
  that parameter in the function, so address(0) bricks every
  proxy reading the beacon.

Gate discipline mirrors batch 4: a caller-identity gate
suppresses only where the gate actually closes the audited
path (proof-length, receiver-sender). Where a gate does not
bind the audited property (destination binding, nonce order,
gas, zero-address), the gate is reported in the gate
analysis, not treated as a suppressor.

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
FAMILY = "deep7"

SPECS = [
    S("bridge_digest_no_destination_chain", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Bridge digest omits the destination chain: the "
             "keccak256 digest construction binds source chain / "
             "origin sender / nonce but contains NO destination-"
             "chain term and no generic chain-id term at all, so "
             "a message valid for one destination chain can be "
             "replayed on any other chain running the same "
             "verifier.",
      fix="Include the destination chain id (dstChainId / "
          "block.chainid of the executing chain) inside the "
          "signed / proven digest, alongside source chain, "
          "origin sender and nonce."),
    S("bridge_bytes_proof_length_unvalidated", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Bridge proof blob length never validated: a "
             "caller-supplied bytes / bytes[] proof is passed "
             "to a verifier by a verify / claim / receive path "
             "and NO require, assert or if condition anywhere "
             "in the contract inspects that proof's .length. "
             "Batch 4 owns the bytes32[] Merkle shape; this is "
             "the opaque proof-blob shape (IAVL / ICS23 / "
             "relayed proofs) it never matches.",
      fix="Validate the proof length before verification: "
          "require(proof.length > 0) and bind it to the "
          "expected proof structure / depth for the scheme "
          "in use."),
    S("bridge_static_gas_limit", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="Static gas limit on a cross-chain dispatch: the "
             "gas forwarded to the destination is a numeric "
             "literal, a constant, or a state variable with a "
             "literal initializer, carried via a gasLimit: / "
             "gas: field. Destination execution costs change "
             "with payload and chain conditions, so a frozen "
             "limit strands messages (out-of-gas on delivery) "
             "or overpays permanently.",
      fix="Take the destination gas limit from the caller "
          "(bounded by a sanity range) or compute it from "
          "the payload, never a frozen literal / constant."),
    S("bridge_receiver_sender_unchecked", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Cross-chain receiver never checks msg.sender: "
             "the receive / execute handler performs proof or "
             "signature verification or state execution but "
             "contains NO msg.sender comparison anywhere, so "
             "any account can invoke the handler directly "
             "instead of only the authorized endpoint / "
             "relayer / messenger being able to deliver.",
      fix="Require msg.sender == the messaging endpoint (and "
          "validate the source peer / remote) at the top of "
          "every cross-chain receive handler."),
    S("bridge_mint_burn_gate_asymmetry", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Bridge mint / burn gate asymmetry: the contract "
             "has both a mint-side (mint / bridgeMint / release "
             "/ unlock) and a burn-side (burn / lock) function "
             "and their caller gates differ - one side is "
             "caller-gated and the other is not. The ungated "
             "side is the weak link: anyone can drive it while "
             "its counterpart was considered sensitive enough "
             "to gate.",
      fix="Gate both sides of the bridge token symmetrically "
          "(same bridge / minter role on mint, burn, lock and "
          "release paths)."),
    S("bridge_nonce_order_unenforced", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Bridge nonce ordering never enforced: the "
             "receive path stores an incoming nonce and the "
             "contract keeps a sequential counter (next / "
             "expected / last / inbound nonce), but NO "
             "condition anywhere compares the incoming nonce "
             "against that counter, so cross-chain messages "
             "can execute out of sequence - breaking protocols "
             "whose messages are order-dependent.",
      fix="Require nonce == expectedNonce (the sequential "
          "counter) in the receive path and advance the "
          "counter exactly once per executed message."),
    S("bridge_proof_nullifier_missing", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Proof accepted with no nullifier recording: a "
             "proof verifier's success gates a mint / release "
             "/ transfer, and the function records NOTHING "
             "keyed by the proof or its public inputs - no "
             "nullifier, spent, used-proof or processed "
             "marker - so the same valid proof can be "
             "submitted again and again for repeated payouts.",
      fix="Record a nullifier (a hash of the proof / public "
          "signals) in a mapping before paying out, and "
          "reject proofs whose nullifier is already recorded."),
    S("bridge_payload_slice_unbounded", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Cross-chain payload sliced without a length "
             "check: a message-execution function directly "
             "indexes, slices or assembly-reads a bytes "
             "payload parameter and NO condition in the "
             "function inspects payload.length, so a short / "
             "malformed payload reverts unpredictably or is "
             "misparsed into attacker-chosen fields.",
      fix="Require payload.length >= the minimum layout size "
          "before any indexing / slicing, or decode with "
          "abi.decode (which bounds-checks) only."),
    S("uups_authorize_upgrade_missing", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="UUPS upgrade authorization missing or empty: "
             "in a UUPSUpgradeable context the "
             "_authorizeUpgrade override is defined with an "
             "EMPTY body (anyone who can reach upgradeTo "
             "upgrades the implementation), or no "
             "_authorizeUpgrade definition appears anywhere "
             "in the source at all.",
      fix="Override _authorizeUpgrade with a real gate "
          "(onlyOwner / role check) in every UUPS "
          "implementation."),
    S("initializer_flag_after_call", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Initialization flag set only after an external "
             "call: an init-named function without an "
             "initializer modifier makes an external call and "
             "assigns its hand-rolled initialized flag AFTER "
             "that call, so during the call the contract is "
             "still uninitialized and a re-entrant initialize "
             "can run a second time.",
      fix="Set the initialized flag BEFORE any external call "
          "(checks-effects-interactions), or use the "
          "OpenZeppelin initializer modifier."),
    S("diamond_selector_collision", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Diamond facet selector collision: the bundle "
             "carries diamond markers and two DISTINCT "
             "non-diamond contracts declare functions with "
             "identical normalized signatures (name + "
             "parameter types), i.e. the same 4-byte selector, "
             "so one facet's route shadows the other's when "
             "installed via diamondCut.",
      fix="Rename one of the colliding facet functions or "
          "change its parameter types; audit every facet's "
          "selector set for duplicates before a diamondCut."),
    S("beacon_implementation_zero_accepted", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Beacon implementation setter accepts "
             "address(0): a beacon-context function assigns "
             "an address parameter to beacon / implementation "
             "storage with NO condition in the function "
             "requiring the parameter != address(0), so a "
             "zero implementation bricks every proxy reading "
             "the beacon.",
      fix="Require newImplementation != address(0) in every "
          "beacon / implementation setter."),
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


def _candidate(item: Dict[str, Any]) -> Dict[str, Any]:
    """Finding with no value destination to classify (config /
    structural defects): still a candidate for review."""
    item["recipient"] = "UNRESOLVED"
    item["report_class"] = "candidate"
    return item


_IDENTITY_GATE_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
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
    """Batch-4 caller-identity gate: only* modifier, msg.sender
    identity comparison, or a role check (incl. one hop into a
    custom modifier's definition)."""
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
    out: List[str] = []
    for m in re.finditer(r"\b(?:require|assert|if)\s*\(", text):
        inner, _ = _balanced(text, m.end() - 1)
        out.append(inner)
    return out


def _split_top(text: str) -> List[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


_PARAM_ATTRS = {"calldata", "memory", "storage", "payable",
                "indexed"}


def _params(fn: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(type, name) pairs from a function signature."""
    sig = fn["signature"]
    i = sig.find("(")
    if i < 0:
        return []
    inner, _ = _balanced(sig, i)
    out: List[Tuple[str, str]] = []
    for part in _split_top(inner):
        toks = [t for t in part.split() if t not in _PARAM_ATTRS]
        if len(toks) >= 2:
            out.append((" ".join(toks[:-1]), toks[-1]))
        elif len(toks) == 1:
            out.append((toks[0], ""))
    return out


def _body(fn: Dict[str, Any]) -> str:
    text = fn["text"]
    return text.split("{", 1)[1] if "{" in text else text


_VALUE_MOVE_RE = re.compile(
    r"\.transfer\s*\(|\.call\s*\{\s*value|_mint\s*\(|\bmint\s*\(|"
    r"safeTransfer|safeMint\s*\(")


# ---------------------------------------------------------------------------
# 1. bridge_digest_no_destination_chain (BRG-001 slice)
# ---------------------------------------------------------------------------

_BINDING_RES = (
    ("source chain", re.compile(
        r"srcChain|sourceChain|originChain|fromChain", re.I)),
    ("origin sender", re.compile(
        r"originSender|srcSender|messageSender|originator|"
        r"\bsender\b|\bsigner\b|\bfrom\b", re.I)),
    ("nonce / message id", re.compile(
        r"nonce|sequence|messageId|msgId", re.I)),
)
_DESTINATION_RE = re.compile(
    r"destinationChain|dstChain|destChain|toChain|destination|"
    r"dstChainId", re.I)
_GENERIC_CHAINID_RE = re.compile(
    r"block\.chainid|(?<![A-Za-z0-9_])chainId(?![A-Za-z0-9_])")


def _digest_inputs(text: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"keccak256\s*\(", text):
        inner, _ = _balanced(text, m.end() - 1)
        em = re.search(r"abi\.encode(?:Packed)?\s*\(", inner)
        if em:
            args, _ = _balanced(inner, em.end() - 1)
            out.append(args)
        else:
            out.append(inner)
    return out


_EIP712_WRAP_RE = re.compile(
    r"\\x19\\x01|\x19\x01|domainSeparator|DOMAIN_SEPARATOR",
    re.I)
_BRIDGE_VOCAB_RE = re.compile(
    r"bridge|message|relay|deliver|process|crosschain|"
    r"srcChain|destinationChain|dstChain", re.I)


def _analyze_digest_no_dest(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "keccak256" not in text:
            continue
        # EIP-712 composition: the chain binding of a typed
        # data digest lives in its domain separator, which
        # the separator lane (eip712_separator_unbound)
        # owns. A permit / typed-data function is not a
        # bridge digest.
        if _EIP712_WRAP_RE.search(text):
            continue
        # Bridge scope: this detector prices cross-chain
        # replay. Same-chain signed actions (permits,
        # forwarder requests, admin signatures) carry no
        # destination-chain concept at all; only engage
        # where bridge / message vocabulary or an explicit
        # source-chain term shows cross-chain intent.
        if not _BRIDGE_VOCAB_RE.search(fn["name"] + " " + text):
            continue
        inputs = _digest_inputs(text)
        if not inputs:
            continue
        joined = " ".join(inputs)
        bindings = [label for label, rx in _BINDING_RES
                    if rx.search(joined)]
        if not bindings:
            continue  # unbound digest: bridge_replay owns it
        if _DESTINATION_RE.search(joined):
            continue
        if _GENERIC_CHAINID_RE.search(joined):
            continue
        consumed = bool(
            re.search(r"verify|execute|claim|process|deliver",
                      fn["name"] + " " + text, re.I)
            or _VALUE_MOVE_RE.search(text)
            or re.search(r"require\s*\([^)]*==", text))
        if not consumed:
            continue
        gated = _caller_gated(fn, scope)
        gate = ("caller gate present, but it binds the "
                "submitter, not the destination chain - the "
                "cross-chain replay stands" if gated else
                "no caller gate; the digest itself is the only "
                "binding and it omits the destination chain")
        detail = spec.detail + (
            f" Observed: '{fn['name']}' builds a digest over "
            f"({joined.strip()[:120]}) binding "
            f"{', '.join(bindings)} with no destination-chain "
            f"or chain-id term.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    gate)
        item = _finish_recipient(spec, item, text)
        if "source chain" in bindings and re.search(
                r"require\s*\([^)]*(srcChain|sourceChain|"
                r"originChain|chainid)[^)]*==", text, re.I):
            # The route is pinned at the other end: the
            # digest binds the source chain and the function
            # hard-requires that exact source, so the message
            # can only ever travel source -> this deployment.
            # The residual is a twin deployment elsewhere -
            # trigger-only, not a candidate.
            item["report_class"] = "trigger_only"
            item["severity"] = "low"
            item["detail"] += (
                " Route analysis: the digest binds the "
                "source chain and the function hard-requires "
                "that source, pinning the route to this "
                "deployment; the residual is a twin "
                "deployment on another destination chain - "
                "classified TRIGGER-ONLY (route pinned).")
            item["gate_analysis"] = (
                "source chain bound in the digest and "
                "hard-required in the function; destination "
                "is this deployment by construction, "
                "reported trigger-only")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 2. bridge_bytes_proof_length_unvalidated (BRG-002 slice)
# ---------------------------------------------------------------------------

def _length_validated(text_all: str, names: List[str]) -> bool:
    conds = _conditions(text_all)
    for name in names:
        len_re = re.compile(r"\b" + re.escape(name) + r"\.length\b")
        if any(len_re.search(c) for c in conds):
            return True
    return False


def _analyze_bytes_proof(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        proof_params = [name for typ, name in _params(fn)
                        if name and "proof" in name.lower()
                        and re.fullmatch(r"bytes(\[\])?", typ)]
        if not proof_params:
            continue
        if not re.search(r"verify|claim|receive|execute|process",
                         fn["name"], re.I):
            continue
        body = _body(fn)
        passed = any(
            re.search(r"\w*[Vv]erify\w*\s*\([^)]*\b"
                      + re.escape(n) + r"\b", body)
            or re.search(r"abi\.decode\s*\(\s*" + re.escape(n)
                         + r"\b", body)
            or re.search(r"\b" + re.escape(n) + r"\s*\[", body)
            for n in proof_params)
        if not passed:
            continue
        if _length_validated(text_all, proof_params):
            continue
        if _caller_gated(fn, scope):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' passes proof "
            f"parameter(s) {proof_params} to a verifier and "
            f"no condition in the contract inspects their "
            f"length.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no proof-length condition found in any "
                    "require / assert / if in the contract "
                    "(bytes / bytes[] proof lane; bytes32[] is "
                    "batch 4's bridge_proof_length_unvalidated)")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. bridge_static_gas_limit (BRG-003 slice)
# ---------------------------------------------------------------------------

_SEND_NAME_RE = re.compile(
    r"send|dispatch|bridge|relay|ccipSend|lzSend", re.I)
_ENDPOINT_CALL_RE = re.compile(
    r"(endpoint|messenger|router|mailbox)\s*\.\s*\w+\s*\(|"
    r"ccipSend\s*\(|lzSend\s*\(", re.I)
_GAS_FIELD_RE = re.compile(
    r"(?:gasLimit|dstGas|gasForCall|gas)\s*:\s*([^,}\)]+)")
_LITERAL_VAR_RES = (
    re.compile(r"\b\w+\s*=\s*(\d[\d_]*)\s*;"),
)


def _literal_vars(text_all: str) -> Dict[str, str]:
    """Names assigned a numeric literal at declaration scope:
    constants / immutables and state vars with literal
    initializers (name -> literal)."""
    out: Dict[str, str] = {}
    for m in re.finditer(
            r"(?:uint\w*|int\w*)\s+(?:(?:public|private|internal|"
            r"constant|immutable)\s+)*([A-Za-z_]\w*)\s*=\s*"
            r"(\d[\d_]*)\s*;", text_all):
        out[m.group(1)] = m.group(2)
    return out


def _analyze_static_gas(src: str, spec: DetectorSpec,
                        compiler: str = "",
                        contract_name: str = ""
                        ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    lit_vars = _literal_vars(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if not (_SEND_NAME_RE.search(fn["name"])
                or _ENDPOINT_CALL_RE.search(text)):
            continue
        param_names = {name for _, name in _params(fn) if name}
        fired_expr = None
        for m in _GAS_FIELD_RE.finditer(text):
            expr = m.group(1).strip()
            if re.fullmatch(r"\d[\d_]*", expr):
                fired_expr = expr
                break
            if re.fullmatch(r"[A-Za-z_]\w*", expr):
                if expr in param_names:
                    continue  # caller-supplied gas
                if expr in lit_vars:
                    fired_expr = expr
                    break
            # anything else is a computed expression: silent
        if fired_expr is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' dispatches cross-chain "
            f"with gas limit expression '{fired_expr}', which "
            f"is "
            + ("a numeric literal." if fired_expr[0].isdigit()
               else f"a variable with the literal initializer "
                    f"{lit_vars.get(fired_expr)}."))
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "gas limit is static (literal / constant / "
                    "literally-initialized state variable); no "
                    "caller parameter or computation supplies it")
        out.append(_candidate(item))
    return out


# ---------------------------------------------------------------------------
# 4. bridge_receiver_sender_unchecked (BRG-004 slice)
# ---------------------------------------------------------------------------

_RECEIVE_NAME_RE = re.compile(
    r"lzReceive|ccipReceive|onMessageReceived|executeMessage|"
    r"receiveMessage|handleMessage|processMessage|deliverMessage",
    re.I)
_VERIFY_OR_EXEC_RE = re.compile(
    r"verify|MerkleProof|ecrecover|signature|proof|"
    r"\.transfer\s*\(|_mint\s*\(|\.call\s*\{|=\s*true\s*;",
    re.I)


_SIG_AUTH_RE = re.compile(
    r"(ecrecover|recoverSigner|ECDSA\.recover|"
    r"SignatureChecker)")


def _analyze_receiver_sender(src: str, spec: DetectorSpec,
                             compiler: str = "",
                             contract_name: str = ""
                             ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _RECEIVE_NAME_RE.search(fn["name"]):
            continue
        text = fn["text"]
        if not _VERIFY_OR_EXEC_RE.search(text):
            continue
        if _IDENTITY_GATE_RE.search(text) or \
                _caller_gated(fn, scope):
            continue  # msg.sender is checked somewhere
        # Signature-authenticated handlers: when execution
        # requires a signature recovered to an authorized
        # signer (or a validator quorum), the signature IS
        # the identity gate and msg.sender is intentionally
        # free - anyone may relay, only authorized messages
        # execute. A bare proof verify does NOT qualify:
        # proofs are bearer instruments, so the endpoint
        # check still matters there.
        if _SIG_AUTH_RE.search(text) and re.search(
                r"require\s*\([^)]*(\bsigner\b|\brecovered)",
                text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' verifies or executes "
            f"a cross-chain message and no msg.sender "
            f"comparison appears anywhere in the function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "verification / execution present, but no "
                    "msg.sender identity comparison and no "
                    "only-endpoint style gate on the handler")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. bridge_mint_burn_gate_asymmetry (BRG-005 slice)
# ---------------------------------------------------------------------------

_MINT_SIDE_RE = re.compile(r"mint|release|unlock", re.I)
_BURN_SIDE_RE = re.compile(r"burn|lock", re.I)


def _analyze_mint_burn_asym(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    entry = [f for f in fns if not re.search(
        r"\b(internal|private)\b", f["signature"])]
    mint_fns = [f for f in entry if _MINT_SIDE_RE.search(f["name"])
                and not _BURN_SIDE_RE.search(f["name"])]
    burn_fns = [f for f in entry if _BURN_SIDE_RE.search(f["name"])
                and not _MINT_SIDE_RE.search(f["name"])]
    if not mint_fns or not burn_fns:
        return []
    mint_gated = any(_caller_gated(f, scope) for f in mint_fns)
    burn_gated = any(_caller_gated(f, scope) for f in burn_fns)
    if mint_gated == burn_gated:
        return []
    ungated = burn_fns if mint_gated else mint_fns
    gated_side = "mint" if mint_gated else "burn"
    out: List[Dict[str, Any]] = []
    for fn in ungated:
        if _caller_gated(fn, scope):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' is ungated while the "
            f"{gated_side}-side function(s) "
            f"{[f['name'] for f in (mint_fns if mint_gated else burn_fns)]} "
            f"are caller-gated.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    f"gate classes differ across the mint/burn "
                    f"pair: {gated_side} side gated, this side "
                    f"has no only* modifier, msg.sender "
                    f"comparison or role check")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 6. bridge_nonce_order_unenforced (BRG-010 slice)
# ---------------------------------------------------------------------------

_COUNTER_RE = re.compile(
    r"\b(next|expected|last|inbound)(Nonce|Sequence)\w*\b")


def _analyze_nonce_order(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    counters = sorted(set(_COUNTER_RE.findall(text_all)))
    counter_names = sorted(set(
        m.group(0) for m in _COUNTER_RE.finditer(text_all)))
    if not counter_names:
        return []
    # An equality comparison anywhere between a nonce-shaped
    # value and the counter enforces the order.
    for cond in _conditions(text_all):
        if "==" in cond and re.search(r"nonce|sequence", cond,
                                      re.I) and any(
                c in cond for c in counter_names):
            return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        nonce_params = [name for _, name in _params(fn)
                        if name and re.search(r"nonce|sequence",
                                              name, re.I)]
        if not nonce_params:
            continue
        writes = any(
            re.search(r"\w+\s*(?:\[[^\]]*\])?\s*=[^=;]*\b"
                      + re.escape(n) + r"\b", _body(fn))
            for n in nonce_params)
        if not writes:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' stores incoming "
            f"nonce parameter(s) {nonce_params} while "
            f"counter(s) {counter_names} exist and no "
            f"condition compares the two.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "sequential counter present but never "
                    "compared with == to the incoming nonce in "
                    "any require / assert / if condition")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 7. bridge_proof_nullifier_missing (BRG-006)
# ---------------------------------------------------------------------------

_VERIFIER_CALL_RE = re.compile(
    r"verifyProof\s*\(|_verifyProof\s*\(|snarkVerify\s*\(|"
    r"groth16Verify\s*\(|plonkVerify\s*\(|\.verify\w*\s*\(|"
    r"(?<![\w.])verify\s*\(")
_PROOF_CTX_RE = re.compile(
    r"proof|publicInput|publicSignal|snark|groth|plonk|zk",
    re.I)
_RECORDING_NAME_RE = re.compile(
    r"nullifier|spent|used|processed|consumed|executed", re.I)
_RECORDING_KEY_RE = re.compile(
    r"proof|nullifier|publicInput|signal|leaf", re.I)


def _has_recording(body: str) -> bool:
    """A state write keyed by the proof / its public inputs:
    an indexed assignment to a nullifier / spent / used /
    processed-style mapping (nested index brackets handled by
    statement-level parsing), a plain assignment to a
    nullifier-named variable, or any indexed assignment whose
    key mentions the proof / public inputs."""
    for stmt in body.split(";"):
        m = re.search(r"(\w+)\s*\[.*\]\s*=[^=]", stmt)
        if m and (_RECORDING_NAME_RE.search(m.group(1))
                  or _RECORDING_KEY_RE.search(stmt)):
            return True
        if re.search(r"\b(nullifier\w*|spent\w*)\s*=[^=]",
                     stmt, re.I):
            return True
    return False


def _analyze_nullifier(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = ""
                       ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if not _VERIFIER_CALL_RE.search(text):
            continue
        if not _PROOF_CTX_RE.search(text):
            continue
        if not (_VALUE_MOVE_RE.search(text) or re.search(
                r"claim|redeem|withdraw|mint|release",
                fn["name"], re.I)):
            continue
        if _has_recording(_body(fn)):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' gates value on a "
            f"proof verification and writes no nullifier / "
            f"spent / used-proof record.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "proof verification gates the payout; no "
                    "state write keyed by the proof or its "
                    "public inputs exists in the function")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 8. bridge_payload_slice_unbounded (BRG-007 slice)
# ---------------------------------------------------------------------------

def _analyze_payload_slice(src: str, spec: DetectorSpec,
                           compiler: str = "",
                           contract_name: str = ""
                           ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        payload_params = [name for typ, name in _params(fn)
                          if name and re.fullmatch(
                              r"bytes(\[\])?", typ)
                          and re.search(r"payload|message", name,
                                        re.I)]
        if not payload_params:
            continue
        body = _body(fn)
        used = False
        length_checked = False
        for n in payload_params:
            if re.search(r"\b" + re.escape(n) + r"\s*\[", body) \
                    or re.search(r"mload\s*\(\s*add\s*\(\s*"
                                 + re.escape(n) + r"\b", body):
                used = True
            if any(re.search(r"\b" + re.escape(n) + r"\.length\b",
                             c) for c in _conditions(text)):
                length_checked = True
        if not used or length_checked:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' indexes / slices "
            f"payload parameter(s) {payload_params} with no "
            f"payload.length condition in the function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "direct payload indexing / slicing present; "
                    "no require / assert / if in the function "
                    "inspects the payload length (abi.decode-"
                    "only handlers stay silent)")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 9. uups_authorize_upgrade_missing (PRX-002 slice)
# ---------------------------------------------------------------------------

def _analyze_uups(src: str, spec: DetectorSpec,
                  compiler: str = "",
                  contract_name: str = ""
                  ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    if "UUPSUpgradeable" not in scope.scoped_text:
        return []
    auth = [f for f in fns if f["name"] == "_authorizeUpgrade"]
    out: List[Dict[str, Any]] = []
    if auth:
        for fn in auth:
            body = _body(fn)
            # fn text ends at the matching brace; the body is
            # everything between the first { and the last }.
            inner = body.rsplit("}", 1)[0] if "}" in body else body
            if inner.strip():
                continue  # some gate statement lives there
            detail = spec.detail + (
                " Observed: '_authorizeUpgrade' is defined "
                "with an empty body in a UUPSUpgradeable "
                "contract.")
            item = _hit(spec, "_authorizeUpgrade",
                        cc._snip(fn["text"]), detail,
                        "_authorizeUpgrade body is empty: no "
                        "gate statement of any kind authorizes "
                        "the upgrade")
            out.append(_candidate(item))
        return out
    detail = spec.detail + (
        " Observed: UUPSUpgradeable inheritance is present "
        "but no _authorizeUpgrade definition appears in the "
        "source. Flattened-source caveat: the definition "
        "could live in a parent contract outside this "
        "flattened bundle, so this shape carries less "
        "certainty than the empty-body shape.")
    item = _hit(spec, "_authorizeUpgrade",
                cc._snip(scope.scoped_text), detail,
                "no _authorizeUpgrade definition found "
                "anywhere in the scoped source (see the "
                "flattened-source caveat in the detail)")
    out.append(_candidate(item))
    return out


# ---------------------------------------------------------------------------
# 10. initializer_flag_after_call (PRX-007 slice)
# ---------------------------------------------------------------------------

_INIT_NAME_RE = re.compile(r"^(initialize|init|setup)", re.I)
_FLAG_DECL_RE = re.compile(
    r"\bbool\s+(?:(?:public|private|internal)\s+)?"
    r"(\w*[Ii]nitializ\w*)\b")
_METHOD_CALL_RE = re.compile(r"(?<![\w.])(\w+)\.(\w+)\s*\(")


def _first_external_call_pos(text: str) -> Optional[int]:
    positions = [c["pos"] for c in cl._external_calls(text)]
    for m in _METHOD_CALL_RE.finditer(text):
        if m.group(1) in ("msg", "block", "tx", "abi", "super"):
            continue
        positions.append(m.start())
    return min(positions) if positions else None


def _analyze_init_flag(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = ""
                       ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    flags = sorted(set(_FLAG_DECL_RE.findall(scope.scoped_text)))
    if not flags:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _INIT_NAME_RE.match(fn["name"]):
            continue
        if "initializer" in fn["signature"]:
            continue  # the modifier IS the guard
        text = fn["text"]
        first_call = _first_external_call_pos(text)
        if first_call is None:
            continue
        late = None
        for flag in flags:
            m = re.search(r"\b" + re.escape(flag)
                          + r"\s*=\s*true\b", text)
            if m and m.start() > first_call:
                late = flag
                break
        if not late:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' assigns {late} = true "
            f"only after its first external call and carries "
            f"no initializer modifier.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "hand-rolled initialized flag written after "
                    "the first external call; no initializer "
                    "modifier on the function")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 11. diamond_selector_collision (PRX-008)
# ---------------------------------------------------------------------------

_DIAMOND_MARKER_RE = re.compile(
    r"diamondCut|IDiamondCut|facets\s*\(", re.I)


def _normalized_sig(fn: Dict[str, Any]) -> str:
    sig = fn["signature"]
    i = sig.find("(")
    if i < 0:
        return fn["name"]
    inner, _ = _balanced(sig, i)
    types = []
    for part in _split_top(inner):
        toks = [t for t in part.split() if t not in _PARAM_ATTRS]
        if len(toks) >= 2:
            types.append(" ".join(toks[:-1]))
        elif toks:
            types.append(toks[0])
    return f"{fn['name']}({','.join(types)})"


def _analyze_diamond(src: str, spec: DetectorSpec,
                     compiler: str = "",
                     contract_name: str = ""
                     ) -> List[Dict[str, Any]]:
    scope, _ = _scope_fns(src, contract_name)
    if not _DIAMOND_MARKER_RE.search(scope.scoped_text):
        return []
    by_sig: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for _path, raw in cl._split_units(src):
        clean = cc._strip_comments(raw)
        spans = cl._contract_spans(clean)
        for fn in cl._extract_functions_pos(clean):
            if "{" not in fn["text"]:
                continue
            owner = next((s for s in spans
                          if s["start"] <= fn["start"] < s["end"]),
                         None)
            if owner is None or owner["kind"] != "contract":
                continue
            if "diamond" in owner["name"].lower():
                continue
            by_sig.setdefault(_normalized_sig(fn), []).append(
                (owner["name"], fn))
    out: List[Dict[str, Any]] = []
    for sig_name, entries in sorted(by_sig.items()):
        contracts = sorted({c for c, _ in entries})
        if len(contracts) < 2:
            continue
        fn_name = entries[0][1]["name"]
        code = "\n".join(cc._snip(e[1]["text"]) for e in entries[:2])
        detail = spec.detail + (
            f" Observed: signature {sig_name} is declared by "
            f"distinct facet contracts {contracts}.")
        item = _hit(spec, fn_name, code, detail,
                    "diamond markers present and the same "
                    "normalized signature appears in two or "
                    "more distinct non-diamond contracts")
        out.append(_candidate(item))
    return out


# ---------------------------------------------------------------------------
# 12. beacon_implementation_zero_accepted (PRX-009)
# ---------------------------------------------------------------------------

_BEACON_CTX_RE = re.compile(r"IBeacon|beacon", re.I)
_ASSIGN_RE = re.compile(
    r"(\w*(?:[Bb]eacon|[Ii]mplementation)\w*)\s*=\s*(\w+)\s*;")


def _analyze_beacon_zero(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    ctx = bool(_BEACON_CTX_RE.search(scope.scoped_text))
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not ctx and "eacon" not in fn["name"].lower():
            continue
        text = fn["text"]
        addr_params = {name for typ, name in _params(fn)
                       if name and "address" in typ}
        conds = _conditions(text)
        for m in _ASSIGN_RE.finditer(_body(fn)):
            storage_var, param = m.group(1), m.group(2)
            if param not in addr_params:
                continue
            checked = any(param in c and "address(0)" in c
                          for c in conds)
            if checked:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' assigns address "
                f"parameter {param} to {storage_var} with no "
                f"zero-address condition on {param}.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "beacon / implementation assignment "
                        "present; no require / assert / if in "
                        "the function compares the parameter "
                        "against address(0)")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


ANALYZERS = {
    "bridge_digest_no_destination_chain": _analyze_digest_no_dest,
    "bridge_bytes_proof_length_unvalidated": _analyze_bytes_proof,
    "bridge_static_gas_limit": _analyze_static_gas,
    "bridge_receiver_sender_unchecked": _analyze_receiver_sender,
    "bridge_mint_burn_gate_asymmetry": _analyze_mint_burn_asym,
    "bridge_nonce_order_unenforced": _analyze_nonce_order,
    "bridge_proof_nullifier_missing": _analyze_nullifier,
    "bridge_payload_slice_unbounded": _analyze_payload_slice,
    "uups_authorize_upgrade_missing": _analyze_uups,
    "initializer_flag_after_call": _analyze_init_flag,
    "diamond_selector_collision": _analyze_diamond,
    "beacon_implementation_zero_accepted": _analyze_beacon_zero,
}


def analyze_deep7_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-7 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors batch 4)
# ---------------------------------------------------------------------------

class DeepAudit7Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 7)"
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
        for item in analyze_deep7_source(
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
                source="deep audit detector batch 7 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit7Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 7) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
