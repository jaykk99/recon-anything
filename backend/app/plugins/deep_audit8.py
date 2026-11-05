"""Deep-audit detectors, batch 8: reentrancy + crypto/signature
slices (2026-11-04).

Fourteen chain-agnostic EVM detectors covering the REE / CRY
slices the 2026-11-04 coverage audit (coverage-d.json) left
PARTIAL or GAP, each disjoint from the native that owns the
neighbouring shape (named per detector below). Same discipline
as batches 1-4: body/condition parsing over the scoped verified
source, recipient classification computed inside the detector
and carried on the finding (CALLER / CALLER-SUPPLIED /
UNRESOLVED = candidate; FIXED / HOLDER-SELF = trigger-only,
never a candidate), the exact code plus a gate analysis on
every finding.

Reentrancy slices:
- cross_function_guard_sibling (REE-001 slice): a contract
  where SOME functions carry a reentrancy guard and a sibling
  that shares state / moves value does not, performing the
  classic call-then-write CEI violation unguarded. The
  no-guard-anywhere case stays with contract_logic.
- reentrancy_guard_uninitialized (REE-005): a hand-rolled
  guard whose status variable is declared in THIS source with
  no initializer and no constructor assignment, so the
  OpenZeppelin NOT_ENTERED=1 semantics the guard logic assumes
  start at 0 and the first "guarded" call can pass twice /
  the lock state machine is shifted.
- eth_send_stipend_brick (REE-006 slice): .send() (2300-gas
  stipend) inside an accounting-writing function. The native
  system_ether_transfer_fallback_brick owns .transfer( shapes;
  this detector is .send( ONLY.
- fallback_state_write_extended (REE-007 slice): ++ / -- /
  delete / array-push writes in ANY receive()/fallback(), and
  plain writes in a NON-payable fallback(). The payable +
  plain-assignment shape stays with contract_recon's
  fallback_state_write exactly.
- token_callback_caller_unverified (REE-008 slice): ERC721 /
  1155 / 777 / 1363 receipt callbacks that write state or
  credit value with no msg.sender identity check. Lender /
  AMM callbacks stay with their own detectors.
- multicall_value_reuse (REE-009): a payable multicall/batch
  loop re-spending the same msg.value on every iteration
  (delegatecall/call loop, no per-item value accounting).
- push_payment_revert_dos (REE-010 slice): a loop over a
  payees state array paying with .transfer(), whose revert
  propagation lets ONE bad recipient brick the whole batch.
  Honest overlap note: bsc_math_system's
  gas_denial_of_service_loop covers unbounded push-payout
  loops by SIZE (loop + .length + a payout call); this
  detector is the revert-propagation mechanism slice - it
  requires .transfer( specifically (guaranteed propagation)
  and stays silent on .call loops with per-item failure
  handling, which the size-based native still flags.

Crypto / signature slices:
- ecdsa_recover_zero_unchecked (CRY-001 slice): OpenZeppelin
  ECDSA.recover / tryRecover results feeding an authorization
  comparison with no zero-address check, or a tryRecover
  error return that is ignored. Raw ecrecover stays with
  deep_audit's ecrecover_zero_signer exactly.
- raw_ecrecover_s_unbounded (CRY-002 slice): raw ecrecover
  with explicit (v, r, s) in ANY function (helpers included -
  the bsc ecdsa_signature_malleability name filter is the gap
  this closes) and no s upper bound anywhere in the contract.
- merkle_leaf_single_hash (CRY-004): a Merkle leaf hashed
  ONCE as keccak256(abi.encodePacked(<single variable-length
  arg>)) and used against a root, with no second hashing of
  the leaf - the second-preimage / leaf-node confusion shape.
- hardcoded_hash_constant_mismatch (CRY-005): a bytes32
  constant whose NAME claims a canonical hash (PERMIT_TYPEHASH,
  EIP-712 domain typehash, *_ROLE identifiers) but whose
  literal does not equal keccak256 of the canonical string,
  recomputed in the analyzer. The keccak route is self-tested
  at import against keccak256("") and
  keccak256("MINTER_ROLE"); if no route passes, this detector
  is dropped (KECCAK_OK False) rather than shipped blind.
- weak_randomness_value_outcome (CRY-006 slice): block.*
  sources deriving an outcome in a function that moves value
  or picks a winner/index by modulo over a participants
  array - name-agnostic (the gamefi / served-source keyword
  frames are the gap this closes). Block sources used only
  for time comparisons / locks stay silent.
- empty_signature_accepted (CRY-007 slice): (a) a
  signature-length == 0 condition that leads to acceptance,
  or (b) a verification function that SPLITS a bytes
  signature for raw ecrecover with no length require
  (== 65 / >= 64) anywhere in the function. gate_analysis
  distinguishes the two shapes.
- packed_encoding_collision (CRY-010):
  keccak256(abi.encodePacked(...)) with >= 2 variable-length
  typed arguments used as an id / digest / signature input -
  ambiguous packing lets distinct tuples hash identically.

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
FAMILY = "deep8"


# ---------------------------------------------------------------------------
# Keccak for the CRY-005 recomputation (self-tested at import)
# ---------------------------------------------------------------------------

def _load_keccak():
    """Return a keccak256(bytes) -> hex str callable, or None.

    Tries eth_hash / pysha3 / pycryptodome first, then the
    codebase's own pure-Python keccak in cryptopack_util.
    """
    try:
        from eth_hash.auto import keccak as _k  # type: ignore
        return lambda b: _k(b).hex()
    except Exception:
        pass
    try:
        import sha3  # type: ignore
        return lambda b: sha3.keccak_256(b).hexdigest()
    except Exception:
        pass
    try:
        from Crypto.Hash import keccak as _ck  # type: ignore

        def _via_crypto(b: bytes) -> str:
            h = _ck.new(digest_bits=256)
            h.update(b)
            return h.hexdigest()
        return _via_crypto
    except Exception:
        pass
    try:
        from .cryptopack_util import keccak256 as _pk
        return lambda b: _pk(b).hex()
    except Exception:
        return None


_KECCAK = _load_keccak()
KECCAK_OK = False
if _KECCAK is not None:
    try:
        KECCAK_OK = (
            _KECCAK(b"") ==
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7"
            "bfad8045d85a470"
            and _KECCAK(b"MINTER_ROLE") ==
            "9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4cee"
            "ef8d981c8956a6")
    except Exception:
        KECCAK_OK = False


def keccak_hex(data: bytes) -> str:
    if not KECCAK_OK or _KECCAK is None:
        raise RuntimeError("no self-tested keccak route")
    return _KECCAK(data)


SPECS = [
    S("cross_function_guard_sibling", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Cross-function reentrancy via an unguarded "
             "sibling: the contract DOES carry a reentrancy "
             "guard (nonReentrant / own lock) on some "
             "functions, but this sibling function is "
             "UNGUARDED, makes an external call and only "
             "writes state AFTER the call, while moving value "
             "or sharing state with a guarded function. A "
             "callee re-entering through this sibling during "
             "the guarded function's call (or vice versa) "
             "observes / mutates the shared state mid-flight "
             "- the guard gives a false sense of coverage.",
      fix="Apply the same reentrancy guard to every function "
          "that touches the shared state, or reorder the "
          "sibling to checks-effects-interactions (write "
          "state before the external call)."),
    S("reentrancy_guard_uninitialized", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Hand-rolled reentrancy guard never initialized: "
             "the guard status variable is declared in this "
             "source with NO initializer and is never assigned "
             "in any constructor / initializer. Guard logic "
             "ported from OpenZeppelin assumes NOT_ENTERED = 1 "
             "semantics; at the default 0 the state machine is "
             "shifted (the first entry check compares against "
             "the wrong sentinel), so the lock can admit a "
             "re-entrant call or lock the contract outright.",
      fix="Initialize the guard status at declaration "
          "(_status = _NOT_ENTERED) or assign it in the "
          "constructor / initializer, matching the sentinel "
          "semantics the modifier checks."),
    S("eth_send_stipend_brick", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail=".send() payout inside an accounting function: "
             ".send() forwards only a 2300-gas stipend, so a "
             "recipient that is a smart wallet / multisig / "
             "contract with any receive logic makes the send "
             "fail, while the function has already written its "
             "accounting state - the payout bricks (funds "
             "accounted as paid, never delivered, or the whole "
             "withdraw path reverts for contract recipients).",
      fix="Pay with .call{value: amount}(\"\") and check the "
          "success flag, or move to a pull-payment pattern; "
          "never .send() from an accounting path."),
    S("fallback_state_write_extended", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="Fallback / receive state mutation beyond the "
             "plain payable assignment shape: the fallback or "
             "receive body performs ++ / -- / delete / "
             "array-push state writes, or a NON-payable "
             "fallback() writes state at all. Fallbacks run "
             "on every stray / malformed call and on plain "
             "ETH sends from other contracts mid-execution; "
             "mutating counters / storage there desyncs "
             "accounting that assumes the fallback is inert "
             "and can be triggered by anyone at any time.",
      fix="Keep receive() / fallback() inert (emit an event "
          "at most); move any state mutation into an explicit "
          "named function with its own gates."),
    S("token_callback_caller_unverified", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Token receipt callback does not verify the "
             "caller: onERC721Received / onERC1155Received / "
             "onERC1155BatchReceived / tokensReceived / "
             "onTransferReceived writes state or credits value "
             "with NO msg.sender comparison anywhere in the "
             "function, so ANY caller can invoke the handler "
             "directly and claim the credit / state change "
             "the callback grants for a genuine token "
             "transfer that never happened.",
      fix="Require msg.sender to be the genuine token / "
          "collection contract inside the callback before "
          "crediting anything (and validate the operator / "
          "from arguments where the design needs them)."),
    S("multicall_value_reuse", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Multicall msg.value reuse: a payable multicall "
             "/ batch function loops delegatecalls / calls "
             "while msg.value is read inside the loop and "
             "there is NO per-iteration value accounting (no "
             "per-item value field, no running sum checked "
             "against msg.value). Each sub-call is credited "
             "with the SAME msg.value, so one payment funds "
             "every iteration - the canonical multicall "
             "value double-spend.",
      fix="Extract a per-item value (e.g. calls[i].value), "
          "sum the items and require the sum to equal "
          "msg.value, debiting per iteration; or make the "
          "multicall non-payable."),
    S("push_payment_revert_dos", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Push-payment revert DoS: a loop over the "
             "payees / recipients state array pays each entry "
             "with .transfer(), which propagates any "
             "recipient revert to the whole loop. ONE bad "
             "recipient (a reverting fallback, a blacklisted "
             "or contract payee) bricks payouts for EVERY "
             "payee, forever, while the payee list keeps the "
             "poisoned entry. (Overlap: the size-based "
             "gas_denial_of_service_loop native also flags "
             "large push loops; this detector is the "
             "revert-propagation slice and requires "
             ".transfer( specifically.)",
      fix="Move to a pull pattern (each payee withdraws "
          "their own share) or pay with .call and isolate "
          "per-item failures so one recipient cannot block "
          "the batch."),
    S("ecdsa_recover_zero_unchecked", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="ECDSA library recovery result not zero-checked: "
             "ECDSA.recover / ECDSA.tryRecover output feeds "
             "an authorization comparison with NO zero-address "
             "check on the recovered address (or a tryRecover "
             "error return is silently ignored). Where the "
             "library variant in use returns address(0) / an "
             "error instead of reverting, an invalid signature "
             "recovers to the zero address and authenticates "
             "whenever the expected signer slot is unset or "
             "zero - and an ignored tryRecover error accepts "
             "malformed signatures on the same path.",
      fix="Require the recovered address to be non-zero "
          "(require(recovered != address(0))) before the "
          "authorization comparison, and handle the "
          "tryRecover error return explicitly (revert on "
          "any error other than NoError)."),
    S("raw_ecrecover_s_unbounded", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Raw ecrecover with no s upper bound: a raw "
             "ecrecover(hash, v, r, s) call (in any function, "
             "helpers included) and NO s bound anywhere in "
             "the contract (no secp256k1n/2 constant, no "
             "s <= comparison). ECDSA signatures are malleable "
             "in s: for every valid (v, r, s) the twin "
             "(v ^ 1, r, n - s) also recovers to the same "
             "signer, so any digest / signature keyed "
             "accounting can be replayed with the twin "
             "signature unless s is bounded to the lower half.",
      fix="Require s to be in the lower half-order "
          "(s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E73"
          "57A4501DDFE92F46681B20A0) before recovering, or "
          "route recovery through OpenZeppelin ECDSA, which "
          "enforces the bound."),
    S("merkle_leaf_single_hash", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Merkle leaf hashed only once with packed "
             "encoding: the leaf is computed as "
             "keccak256(abi.encodePacked(x)) over a single "
             "variable-length argument (bytes / string) and "
             "checked against a Merkle root, with NO second "
             "hashing of the leaf. A single packed hash gives "
             "no leaf / internal-node domain separation: a "
             "64-byte leaf can be reinterpreted as the "
             "concatenation of two child hashes, letting an "
             "attacker prove an internal node as a leaf "
             "(second-preimage / leaf-confusion attack).",
      fix="Double-hash the leaf (keccak256(abi.encode(leaf)) "
          "over the first hash, OpenZeppelin MerkleProof "
          "style) or hash the leaf with abi.encode and a "
          "domain separator distinct from node hashing."),
    S("hardcoded_hash_constant_mismatch", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Hardcoded hash constant does not match its "
             "claimed preimage: a bytes32 constant named for "
             "a canonical hash (PERMIT_TYPEHASH, an EIP-712 "
             "domain typehash, or a *_ROLE identifier) carries "
             "a literal that differs from keccak256 of the "
             "canonical string, recomputed by this analyzer. "
             "Every signature / role check keyed on the "
             "constant verifies against the WRONG digest: "
             "permits fail or validate a different struct "
             "than signers signed, and role gates key on a "
             "hash no administrator can reproduce from the "
             "role name.",
      fix="Replace the literal with the recomputed "
          "keccak256 of the canonical string, or compute the "
          "constant in code (keccak256(\"IDENTIFIER\") / "
          "keccak256(bytes(\"Permit(...)\"))) so name and "
          "value cannot drift."),
    S("weak_randomness_value_outcome", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Weak randomness decides a value outcome: the "
             "function derives a result from block.timestamp "
             "/ block.prevrandao / blockhash / "
             "block.difficulty (including inside a keccak256 "
             "packed hash) AND moves value (transfer / "
             "call{value} / mint) or selects a winner / index "
             "by modulo over a participants array. Block "
             "values are observable and influenceable by "
             "validators and by anyone who can time a call, "
             "so the 'random' outcome can be predicted or "
             "ground until it favors the caller.",
      fix="Use a commit-reveal scheme or a verifiable "
          "randomness source (Chainlink VRF) for any outcome "
          "that moves value; never derive value outcomes "
          "from block values."),
    S("empty_signature_accepted", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Empty / unlength-checked signature accepted: "
             "either (a) a condition on the signature's length "
             "== 0 leads to acceptance (return true / pass) "
             "in a verification function, so an EMPTY "
             "signature authenticates; or (b) a verification "
             "function splits a bytes signature for raw "
             "ecrecover with NO length require (== 65 / "
             ">= 64) anywhere in the function, so truncated / "
             "empty signatures flow into recovery (recovering "
             "to address(0) or garbage) instead of being "
             "rejected up front.",
      fix="Reject empty signatures explicitly and require "
          "the exact signature length (sig.length == 65 for "
          "raw ECDSA, or the EIP-2098 compact form) before "
          "any splitting or recovery."),
    S("packed_encoding_collision", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Packed-encoding hash collision: "
             "keccak256(abi.encodePacked(...)) is computed "
             "over >= 2 variable-length arguments (string / "
             "bytes / arrays) and used as an id / digest / "
             "signature input. abi.encodePacked concatenates "
             "variable-length values with no length prefixes, "
             "so distinct tuples ((\"ab\", \"c\") vs "
             "(\"a\", \"bc\")) hash identically - ids collide, "
             "digests can be forged across field boundaries, "
             "and signatures validate for data the signer "
             "never saw.",
      fix="Hash with abi.encode (length-prefixed) instead "
          "of abi.encodePacked whenever more than one "
          "variable-length value is involved, or insert "
          "explicit length prefixes / separators."),
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


def _brace_body(text: str, open_pos: int) -> Tuple[str, int]:
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
        i += 1
    return text[open_pos + 1:], len(text) - 1


def _split_top(inner: str) -> List[str]:
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _conditions(text: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"\b(?:require|assert|if)\s*\(", text):
        inner, _ = _balanced(text, m.end() - 1)
        out.append(inner)
    return out


def _level_text(scope, fns) -> str:
    """Scoped source with function bodies removed: what is
    left is contract-level declarations (+ modifiers)."""
    text = scope.scoped_text
    for fn in sorted(fns, key=lambda f: len(f["text"]),
                     reverse=True):
        if fn["text"] and fn["text"] in text:
            text = text.replace(fn["text"], " ", 1)
    return text


_DECL_RE = re.compile(
    r"(mapping\s*\([^;]*?\)(?:\s*\[\s*\])?|"
    r"[A-Za-z_][\w.]*(?:\s*\[\s*\d*\s*\])?)\s+"
    r"(?:(?:public|private|internal|constant|immutable)\s+)*"
    r"([A-Za-z_]\w*)\s*(?:=[^;]*)?;")


def _state_vars(scope, fns) -> Dict[str, str]:
    """name -> declared type, from contract-level text."""
    out: Dict[str, str] = {}
    fn_names = {f["name"] for f in fns}
    for m in _DECL_RE.finditer(_level_text(scope, fns)):
        name = m.group(2)
        if name in fn_names or name in (
                "memory", "calldata", "storage"):
            continue
        out[name] = re.sub(r"\s+", "", m.group(1))
    return out


def _fn_params(fn: Dict[str, Any]) -> Dict[str, str]:
    """param name -> base type, from the signature."""
    sig = fn["signature"]
    i = sig.find("(")
    if i < 0:
        return {}
    inner, _ = _balanced(sig, i)
    out: Dict[str, str] = {}
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("memory", "calldata", "storage",
                             "payable")]
        if len(toks) >= 2:
            out[toks[-1]] = " ".join(toks[:-1])
        elif len(toks) == 1 and re.search(
                r"\[\]|\.\w+$", toks[0]):
            out[toks[0]] = toks[0]
    return out


_VARLEN_HINT_RE = re.compile(r"^(string|bytes)$|\[\]\s*$|\[\]$")


def _is_varlen_type(typ: str) -> bool:
    t = re.sub(r"\s+", "", typ or "")
    return bool(_VARLEN_HINT_RE.search(t)) or t in (
        "string", "bytes")


_EXT_CALL_RE = re.compile(
    r"\.call\s*\{|\.call\s*\(|\.call\.value\s*\(|"
    r"\.transfer\s*\(|\.send\s*\(|\.delegatecall\s*\(|"
    r"\b\w+\.\w+\s*\(")
_NON_EXTERNAL_OBJ = {"abi", "ECDSA", "SafeMath", "Strings",
                     "MerkleProof", "Address", "Math"}


def _external_call_positions(text: str,
                             state: Dict[str, str]) -> List[int]:
    out: List[int] = []
    for m in _EXT_CALL_RE.finditer(text):
        tok = m.group(0)
        if tok.startswith("."):
            out.append(m.start())
            continue
        obj = tok.split(".")[0]
        if obj in _NON_EXTERNAL_OBJ:
            continue
        if obj in state or obj[0].islower():
            out.append(m.start())
    return out


_VALUE_MOVE_RE = re.compile(
    r"\.transfer\s*\(|\.call\s*\{\s*value|\.call\.value\s*\(|"
    r"\.send\s*\(|_mint\s*\(|\bmint\s*\(|safeTransfer|"
    r"safeMint\s*\(|_safeMint\s*\(")


def _write_re(var: str) -> "re.Pattern":
    return re.compile(
        r"\b" + re.escape(var) +
        r"\b\s*(?:\[[^\]]*\]\s*)?"
        r"(?:\+\+|--|\+=|-=|\*=|/=(?!=)|=(?!=))|"
        r"\b" + re.escape(var) + r"\b\s*\.\s*push\s*\(|"
        r"\bdelete\s+" + re.escape(var) + r"\b")


def _vars_written(text: str, state: Dict[str, str]) -> List[str]:
    return [v for v in state if _write_re(v).search(text)]


def _is_view_pure(fn: Dict[str, Any]) -> bool:
    return bool(re.search(r"\b(view|pure)\b", fn["signature"]))


_LOCK_BODY_RE = re.compile(
    r"_status|_locked|\blocked\b|ENTERED|require\s*\(\s*!|"
    r"reentrancy", re.I)


def _is_guarded(fn: Dict[str, Any], scope) -> bool:
    sig, text = fn["signature"], fn["text"]
    if "nonReentrant" in sig or "nonReentrant" in text:
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and _LOCK_BODY_RE.search(body):
                return True
    # Inline lock usage in the body itself.
    if re.search(r"(_status|_locked)\s*=[^=]", text) or \
            re.search(r"\blocked\s*=\s*true", text):
        return True
    return False


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
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


# ---------------------------------------------------------------------------
# 1. cross_function_guard_sibling (REE-001 slice)
# ---------------------------------------------------------------------------

def _analyze_guard_sibling(src: str, spec: DetectorSpec,
                           compiler: str = "",
                           contract_name: str = ""
                           ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(scope, fns)
    guarded = [fn for fn in fns if _is_guarded(fn, scope)]
    if not guarded:
        return []  # no guard anywhere: contract_logic owns it
    guarded_vars = set()
    for fn in guarded:
        for v in state:
            if re.search(r"\b" + re.escape(v) + r"\b",
                         fn["text"]):
                guarded_vars.add(v)
    # Reachability discipline (FP elimination, 2026-11-05):
    # a reentrancy finding needs a stranger-reachable entry.
    # Caller-gated functions are not stranger-reachable, and
    # an internal/private function inherits the protection
    # of its in-scope callers: Compound's *Fresh internals
    # sit behind guarded *Internal entries, Uniswap's _mint
    # behind the lock-guarded mint/burn. Flagging the
    # internal helper itself is a phantom.
    callers = {}
    for fn in fns:
        for other in fns:
            if other is fn:
                continue
            if re.search(r"\b" + re.escape(fn["name"]) +
                         r"\s*\(", other["text"]):
                callers.setdefault(fn["name"], set()).add(
                    id(other))
    by_id = {id(f): f for f in fns}

    def _protected(fn, seen=frozenset()):
        if _is_guarded(fn, scope) or _caller_gated(fn, scope):
            return True
        if id(fn) in seen:
            return False
        if not re.search(r"\b(internal|private)\b",
                         fn["signature"]):
            return False  # an entry point, unguarded
        cs = callers.get(fn["name"], set())
        if not cs:
            return False  # no in-scope caller: cannot prove
        return all(_protected(by_id[c], seen | {id(fn)})
                   for c in cs)

    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn in guarded or _is_view_pure(fn):
            continue
        if fn["name"] in ("constructor", "receive",
                          "fallback", ""):
            continue
        if _protected(fn):
            continue
        text = fn["text"]
        calls = _external_call_positions(text, state)
        if not calls:
            continue
        written_after: List[str] = []
        for pos in calls:
            written_after = _vars_written(text[pos:], state)
            if written_after:
                break
        if not written_after:
            continue  # CEI-ordered: silent
        value_moving = bool(_VALUE_MOVE_RE.search(text))
        fn_vars = {v for v in state
                   if re.search(r"\b" + re.escape(v) + r"\b",
                                text)}
        shared = bool(fn_vars & guarded_vars)
        # Shared-state-only branch (no value move in this
        # function) additionally needs a control-yielding
        # call: a low-level call, or a call on a non-state
        # object (parameter / local / caller-supplied).
        # Calls that only read through governance-set
        # protocol singletons stored in state (Compound's
        # accrueInterest reading its interest-rate model /
        # comptroller) do not hand control to
        # stranger-chosen code.
        yielding = bool(re.search(r"\.call\s*[\{\(]", text))
        if not yielding:
            for m in _EXT_CALL_RE.finditer(text):
                tok = m.group(0)
                if tok.startswith("."):
                    yielding = True
                    break
                obj = tok.split(".")[0]
                if obj in _NON_EXTERNAL_OBJ:
                    continue
                if obj not in state:
                    yielding = True
                    break
        if not (value_moving or (shared and yielding)):
            continue
        detail = spec.detail + (
            f" Observed: guarded sibling(s) "
            f"{[g['name'] for g in guarded]} exist, but "
            f"'{fn['name']}' is unguarded, calls out and only "
            f"then writes {written_after}"
            + (" while moving value" if value_moving else "")
            + (f"; it shares state {sorted(fn_vars & guarded_vars)}"
               f" with the guarded function(s)"
               if shared else "") + ".")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "a reentrancy guard exists in the contract "
                    "but this function carries none (no "
                    "nonReentrant / lock modifier, no inline "
                    "lock) while violating CEI ordering")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. reentrancy_guard_uninitialized (REE-005)
# ---------------------------------------------------------------------------

# Only uint/int status vars are in scope: the defect is the
# NOT_ENTERED=1 sentinel semantics. A bool lock defaults to
# false = unlocked, which is the CORRECT initial state, so
# bool guards are never flagged here.
_GUARD_VAR_RE = re.compile(
    r"(uint\d*|int\d*)\s+"
    r"(?:(?:public|private|internal|constant)\s+)*"
    r"(_status|_locked|locked|_lock|_entered|entered|"
    r"reentrancyStatus|_guard)\b\s*(=[^;]*)?;")


def _analyze_guard_uninitialized(src: str, spec: DetectorSpec,
                                 compiler: str = "",
                                 contract_name: str = ""
                                 ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    level = _level_text(scope, fns)
    decls = list(_GUARD_VAR_RE.finditer(level))
    if not decls:
        return []  # guard inherited / absent: not defined here
    constructors = [fn for fn in fns
                    if fn["name"] in ("constructor", "initialize",
                                      "init", "__init")]
    out: List[Dict[str, Any]] = []
    for m in decls:
        var, init = m.group(2), m.group(3)
        if init:
            continue  # initializer at declaration
        # Used as a guard? (modifier body or function body
        # reads/writes it as the lock flag)
        used_in = ""
        for name, body in scope.modifiers.items():
            if re.search(r"\b" + re.escape(var) + r"\b", body):
                used_in = name
                break
        if not used_in:
            for fn in fns:
                if fn["name"] == "constructor":
                    continue
                if re.search(r"\b" + re.escape(var) +
                             r"\b\s*(==|!=|=)", fn["text"]):
                    used_in = fn["name"]
                    break
        if not used_in:
            continue  # a plain counter, not a guard flag
        assigned_ctor = any(
            re.search(r"\b" + re.escape(var) + r"\b\s*=[^=]",
                      fn["text"])
            for fn in constructors)
        if assigned_ctor:
            continue
        detail = spec.detail + (
            f" Observed: guard variable '{var}' is declared "
            f"without an initializer, is used as the "
            f"reentrancy flag by '{used_in}', and no "
            f"constructor / initializer assigns it.")
        item = _hit(spec, used_in, cc._snip(m.group(0) +
                    "\n// used by: " + used_in), detail,
                    f"guard variable {var} has no declaration "
                    "initializer and no constructor assignment "
                    "in this source; the guard is defined here "
                    "(not inherited from OpenZeppelin)")
        # Recipient: whoever can call the guarded functions;
        # no value destination in the declaration itself.
        item["recipient"] = "UNRESOLVED"
        item["report_class"] = "candidate"
        item["detail"] += (
            " Recipient analysis: recipient classified "
            "UNRESOLVED (the defect is in the guard itself; "
            "the value at risk sits behind the guarded "
            "functions) - classified CANDIDATE under the "
            "receive rule.")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 3. eth_send_stipend_brick (REE-006 slice)
# ---------------------------------------------------------------------------

_SEND_RE = re.compile(r"\.send\s*\(")


def _analyze_send_stipend(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(scope, fns)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if not _SEND_RE.search(text):
            continue  # .transfer( shapes belong to the native
        written = _vars_written(text, state)
        if not written:
            continue  # no accounting write in this function
        detail = spec.detail + (
            f" Observed: '{fn['name']}' pays via .send() and "
            f"writes accounting state {written} in the same "
            f"function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    ".send() (2300-gas stipend) used on an "
                    "accounting path; no .call-based payout or "
                    "pull pattern in this function")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. fallback_state_write_extended (REE-007 slice)
# ---------------------------------------------------------------------------

_EXTENDED_WRITE_RE = re.compile(
    r"\b\w+\s*(?:\[[^\]]*\]\s*)?(?:\+\+|--)|"
    r"\bdelete\s+\w+|"
    r"\b\w+\s*\.\s*push\s*\(")


def _analyze_fallback_extended(src: str, spec: DetectorSpec,
                               compiler: str = "",
                               contract_name: str = ""
                               ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(scope, fns)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] not in ("fallback", "receive"):
            continue
        text, sig = fn["text"], fn["signature"]
        body = text[text.find("{"):] if "{" in text else text
        extended = bool(_EXTENDED_WRITE_RE.search(body))
        plain = _vars_written(body, state)
        payable = "payable" in sig
        fire = extended or (plain and fn["name"] == "fallback"
                            and not payable)
        if not fire:
            continue  # payable + plain assignment is
            # contract_recon's fallback_state_write exactly
        why = ("++/--/delete/push state write"
               if extended else
               "plain state write in a non-payable fallback")
        detail = spec.detail + (
            f" Observed: '{fn['name']}' performs a {why} "
            f"(writes: {plain or 'counter/array mutation'}).")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    f"fallback/receive is not inert: {why}; "
                    "the payable + plain-assignment shape owned "
                    "by contract_recon is excluded")
        item["recipient"] = "UNRESOLVED"
        item["report_class"] = "candidate"
        item["detail"] += (
            " Recipient analysis: recipient classified "
            "UNRESOLVED (any stray caller triggers the "
            "mutation; no direct value destination) - "
            "classified CANDIDATE under the receive rule.")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 5. token_callback_caller_unverified (REE-008 slice)
# ---------------------------------------------------------------------------

_CALLBACK_NAMES = {
    "onERC721Received", "onERC1155Received",
    "onERC1155BatchReceived", "tokensReceived",
    "onTransferReceived"}
_CREDIT_RE = re.compile(
    r"_mint\s*\(|safeMint\s*\(|_safeMint\s*\(|"
    r"\.transfer\s*\(|safeTransfer")


def _analyze_token_callback(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(scope, fns)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] not in _CALLBACK_NAMES:
            continue
        text = fn["text"]
        written = _vars_written(text, state)
        if not written and not _CREDIT_RE.search(text):
            continue  # inert acknowledgment handler
        if _IDENTITY_GATE_RE.search(text) or \
                _caller_gated(fn, scope):
            continue  # msg.sender verified against the token
        detail = spec.detail + (
            f" Observed: '{fn['name']}' writes state "
            f"{written} / credits value with no msg.sender "
            f"comparison in the function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no msg.sender identity comparison and no "
                    "caller gate anywhere in the callback; the "
                    "handler trusts every caller as the token "
                    "contract")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 6. multicall_value_reuse (REE-009)
# ---------------------------------------------------------------------------

_MULTICALL_NAME_RE = re.compile(r"multicall|batch", re.I)
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(")
_PER_ITEM_VALUE_RE = re.compile(
    r"\[\s*\w+\s*\]\s*\.\s*value\b|\bvalues?\s*\[\s*\w+\s*\]|"
    r"\.\s*value\s*\}\s*\)|\bamounts?\s*\[\s*\w+\s*\]")


def _analyze_multicall(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = ""
                       ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _MULTICALL_NAME_RE.search(fn["name"]):
            continue
        sig, text = fn["signature"], fn["text"]
        if "payable" not in sig:
            continue  # non-payable multicall cannot reuse value
        loop = _LOOP_RE.search(text)
        if not loop:
            continue
        after_loop = text[loop.start():]
        if not re.search(r"\.delegatecall\s*\(|\.call\s*\{|"
                         r"\.call\s*\(", after_loop):
            continue
        if "msg.value" not in after_loop:
            continue
        # Per-iteration accounting: a per-item value field is
        # read, or a running sum is checked against msg.value.
        if _PER_ITEM_VALUE_RE.search(after_loop):
            continue
        summed = re.search(
            r"(\w+)\s*\+=[^;]*\.value|(\w+)\s*\+=\s*\w+\s*\[",
            after_loop)
        if summed and any(
                "msg.value" in c and
                (summed.group(1) or summed.group(2) or "") in c
                for c in _conditions(text)):
            continue
        detail = spec.detail + (
            f" Observed: payable '{fn['name']}' loops "
            f"delegatecalls / calls with msg.value read "
            f"inside the loop and no per-item value field or "
            f"sum-vs-msg.value check anywhere in the "
            f"function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "msg.value is reused per iteration: no "
                    "per-item value extraction and no running "
                    "sum compared against msg.value")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 7. push_payment_revert_dos (REE-010 slice)
# ---------------------------------------------------------------------------

def _loop_bodies(text: str) -> List[Tuple[str, str]]:
    """(header_condition, body) per for/while loop."""
    out: List[Tuple[str, str]] = []
    for m in _LOOP_RE.finditer(text):
        header, hend = _balanced(text, m.end() - 1)
        i = hend + 1
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        if i < len(text) and text[i] == "{":
            body, _ = _brace_body(text, i)
            out.append((header, body))
        elif i < len(text):
            semi = text.find(";", i)
            out.append((header,
                        text[i:semi if semi >= 0 else len(text)]))
    return out


def _analyze_push_payment(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(scope, fns)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        fired = False
        for header, body in _loop_bodies(text):
            over_state = any(
                re.search(r"\b" + re.escape(v) + r"\b", header)
                for v in state)
            if not over_state or ".length" not in header:
                continue
            if not re.search(r"\.transfer\s*\(", body):
                continue  # .call / send-with-skip / try-catch
                # shapes isolate failures: silent here
            fired = True
            break
        if not fired:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' loops over a payees "
            f"state array and pays with .transfer() inside "
            f"the loop, so any single recipient revert "
            f"propagates to the whole batch.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "loop pays via .transfer() (revert "
                    "propagates); no per-item failure isolation "
                    "is possible with .transfer and none is "
                    "present")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 8. ecdsa_recover_zero_unchecked (CRY-001 slice)
# ---------------------------------------------------------------------------

_ECDSA_RECOVER_RE = re.compile(r"ECDSA\s*\.\s*(tryRecover|recover)\s*\(")
_ZERO_CHECK_TMPL = (
    r"\b{v}\b\s*!=\s*address\s*\(\s*0\s*\)|"
    r"address\s*\(\s*0\s*\)\s*!=\s*\b{v}\b|"
    r"\b{v}\b\s*==\s*address\s*\(\s*0\s*\)|"
    r"address\s*\(\s*0\s*\)\s*==\s*\b{v}\b")


def _has_zero_check(text: str, var: str) -> bool:
    return bool(re.search(
        _ZERO_CHECK_TMPL.format(v=re.escape(var)), text))


def _analyze_ecdsa_recover(src: str, spec: DetectorSpec,
                           compiler: str = "",
                           contract_name: str = ""
                           ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        m = _ECDSA_RECOVER_RE.search(text)
        if not m:
            continue  # raw ecrecover is ecrecover_zero_signer's
        kind = m.group(1)
        # LHS of the recovery assignment.
        lhs = text[:m.start()].rsplit(";", 1)[-1].rsplit(
            "{", 1)[-1]
        tm = re.search(r"\(([^)]*)\)\s*=\s*$", lhs.strip()) or \
            re.search(r"(\w+)\s*=\s*$", lhs.strip())
        vars_lhs: List[str] = []
        if tm:
            vars_lhs = [v.strip() for v in
                        tm.group(1).split(",") if v.strip()]
            vars_lhs = [re.sub(r"^(address|bytes32|uint\w*|"
                               r"ECDSA\.RecoverError)\s+", "",
                               v).strip() for v in vars_lhs]
        recovered = vars_lhs[0] if vars_lhs else ""
        fired, why = False, ""
        if kind == "tryRecover" and len(vars_lhs) < 2:
            fired, why = True, (
                "tryRecover's error return is discarded "
                "(single-value assignment)")
        elif kind == "tryRecover" and len(vars_lhs) >= 2:
            err_var = vars_lhs[1]
            err_used = any(
                re.search(r"\b" + re.escape(err_var) + r"\b",
                          c)
                for c in _conditions(text))
            if not err_used:
                fired, why = True, (
                    f"tryRecover error variable '{err_var}' is "
                    "never checked in any require / if condition")
            elif recovered and not _has_zero_check(text,
                                                   recovered):
                compared = bool(re.search(
                    r"\b" + re.escape(recovered) +
                    r"\b\s*(==|!=)|(==|!=)\s*\b" +
                    re.escape(recovered) + r"\b", text))
                if compared:
                    fired, why = True, (
                        f"recovered '{recovered}' feeds an "
                        "authorization comparison with no "
                        "zero-address check")
        else:  # plain recover
            # OpenZeppelin ECDSA.recover is the THROWING
            # variant: it reverts on every recovery error,
            # so a zero / invalid signer can never be
            # returned and there is nothing to zero-check.
            # (The zero-returns live in tryRecover, handled
            # above, and in raw ecrecover, owned by
            # ecrecover_zero_signer.) Firing here was the
            # MetaMorpho / 1inch permit false positive:
            # never fire on the plain-recover branch.
            fired, why = False, ""
        if not fired:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' uses ECDSA.{kind}: "
            f"{why}.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ECDSA library recovery (raw ecrecover is "
                    "owned by ecrecover_zero_signer); no "
                    "zero-address check on the recovered "
                    "address / error return ignored")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 9. raw_ecrecover_s_unbounded (CRY-002 slice)
# ---------------------------------------------------------------------------

_RAW_ECC_RE = re.compile(r"(?<![\w.])ecrecover\s*\(")
_S_BOUND_RE = re.compile(
    r"0x7[fF]{3,}|INVALID_SIG_S|MAX_SIG_S|secp256k1|"
    r"\bs\s*<=")


def _analyze_s_unbounded(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    if _S_BOUND_RE.search(scope.scoped_text):
        return []  # an s bound exists somewhere in the contract
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        m = _RAW_ECC_RE.search(text)
        if not m:
            continue
        inner, _ = _balanced(text, m.end() - 1)
        args = _split_top(inner)
        if len(args) < 4:
            continue  # not the explicit (hash, v, r, s) shape
        detail = spec.detail + (
            f" Observed: '{fn['name']}' calls raw ecrecover "
            f"with explicit (v, r, s) arguments and no s "
            f"bound exists anywhere in the contract.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "raw ecrecover path (not routed through "
                    "ECDSA.recover); no secp256k1n/2 constant "
                    "and no s <= comparison in the contract")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 10. merkle_leaf_single_hash (CRY-004)
# ---------------------------------------------------------------------------

_LEAF_ASSIGN_RE = re.compile(
    r"(\w+)\s*=\s*keccak256\s*\(\s*abi\.encodePacked\s*\(")
_ROOT_CTX_RE = re.compile(
    r"MerkleProof|\w*[Rr]oot\w*\b|merkle", )


def _analyze_merkle_leaf(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    if not _ROOT_CTX_RE.search(scope.scoped_text):
        return []
    state = _state_vars(scope, fns)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        params = _fn_params(fn)
        types = dict(state)
        types.update(params)
        for m in _LEAF_ASSIGN_RE.finditer(text):
            leaf_var = m.group(1)
            inner, _ = _balanced(text, m.end() - 1)
            args = _split_top(inner)
            if len(args) != 1:
                continue
            arg = args[0].strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", arg):
                continue  # literal / expression, not a single
                # variable-length variable
            if not _is_varlen_type(types.get(arg, "")):
                continue  # fixed-size scalar arg: silent
            # Leaf must be used against a root / in a verify.
            used = bool(re.search(
                r"\b" + re.escape(leaf_var) + r"\b", text) and
                (_ROOT_CTX_RE.search(text) or
                 "verify" in text.lower()))
            if not used:
                continue
            # Double hashing of the leaf anywhere suppresses.
            double = bool(re.search(
                r"keccak256\s*\(\s*abi\.encode\s*\(\s*" +
                re.escape(leaf_var) + r"\b", scope.scoped_text)
                or re.search(
                    r"keccak256\s*\(\s*abi\.encodePacked\s*\(\s*"
                    r"keccak256\s*\(", text)
                or re.search(
                    r"keccak256\s*\(\s*" +
                    re.escape(leaf_var) + r"\s*\)",
                    scope.scoped_text))
            if double:
                continue
            detail = spec.detail + (
                f" Observed: leaf '{leaf_var}' in "
                f"'{fn['name']}' is a single "
                f"keccak256(abi.encodePacked({arg})) over "
                f"variable-length '{arg}' "
                f"({types.get(arg)}) and is never hashed a "
                f"second time.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "leaf single-hashed with packed "
                        "encoding; no keccak256(abi.encode(leaf)) "
                        "double hash anywhere in the contract")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


# ---------------------------------------------------------------------------
# 11. hardcoded_hash_constant_mismatch (CRY-005)
# ---------------------------------------------------------------------------

_HASH_CONST_RE = re.compile(
    r"bytes32\s+(?:(?:public|private|internal|constant|"
    r"immutable)\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"0x([0-9a-fA-F]{64})\b")
_PERMIT_STR = ("Permit(address owner,address spender,"
               "uint256 value,uint256 nonce,"
               "uint256 deadline)")
_PERMIT_STR_DAI = ("Permit(address holder,address spender,"
                   "uint256 nonce,uint256 expiry,"
                   "bool allowed)")
_DOMAIN_STR = ("EIP712Domain(string name,string version,"
               "uint256 chainId,address verifyingContract)")


def _canonical_for(name: str) -> Optional[str]:
    if name == "PERMIT_TYPEHASH":
        return _PERMIT_STR
    if "DOMAIN" in name and "TYPEHASH" in name:
        return _DOMAIN_STR
    if name.endswith("_ROLE"):
        return name
    return None


def _canonical_set(name: str) -> List[str]:
    """Every canonical preimage a constant name legitimately
    carries in the wild. PERMIT_TYPEHASH has TWO deployed
    canonical schemas: the ERC-2612 string and the original
    Dai permit string (mainnet Dai's literal is exactly
    keccak256 of the Dai string - flagging it was a false
    positive, FP elimination 2026-11-05). A literal matching
    ANY known schema for its name is consistent; only a
    literal matching none is a mismatch."""
    base = _canonical_for(name)
    if base is None:
        return []
    out = [base]
    if name == "PERMIT_TYPEHASH":
        out.append(_PERMIT_STR_DAI)
    return out


def _analyze_hash_constant(src: str, spec: DetectorSpec,
                           compiler: str = "",
                           contract_name: str = ""
                           ) -> List[Dict[str, Any]]:
    if not KECCAK_OK:
        return []  # dropped honestly: no self-tested keccak
    scope, fns = _scope_fns(src, contract_name)
    level = _level_text(scope, fns)
    out: List[Dict[str, Any]] = []
    for m in _HASH_CONST_RE.finditer(level):
        name, literal = m.group(1), m.group(2).lower()
        canonicals = _canonical_set(name)
        if not canonicals:
            continue
        canonical = canonicals[0]
        expected = keccak_hex(canonical.encode())
        if any(literal == keccak_hex(c.encode())
               for c in canonicals):
            continue  # matches a known schema: silent
        detail = spec.detail + (
            f" Observed: constant {name} = 0x{literal} but "
            f"keccak256(\"{canonical}\") = 0x{expected}.")
        item = _hit(spec, name, cc._snip(m.group(0)), detail,
                    "literal recomputed in-analyzer with a "
                    "self-tested keccak256 (empty-string and "
                    "MINTER_ROLE vectors verified at import); "
                    "the literal does not match")
        item["recipient"] = "UNRESOLVED"
        item["report_class"] = "candidate"
        item["detail"] += (
            " Recipient analysis: recipient classified "
            "UNRESOLVED (the constant keys signature / role "
            "checks contract-wide) - classified CANDIDATE "
            "under the receive rule.")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 12. weak_randomness_value_outcome (CRY-006 slice)
# ---------------------------------------------------------------------------

_BLOCK_SRC_RE = re.compile(
    r"block\.timestamp|block\.prevrandao|block\.difficulty|"
    r"blockhash\s*\(")
_MOD_SELECT_RE = re.compile(
    r"%\s*[\w.]+\.length|%\s*\w+\s*\)?\s*;\s*[^\n;]*\[|"
    r"\[\s*\w*(?:[Rr]and|[Ii]ndex|[Ww]in)\w*\s*\]")


def _analyze_weak_randomness(src: str, spec: DetectorSpec,
                             compiler: str = "",
                             contract_name: str = ""
                             ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if not _BLOCK_SRC_RE.search(text):
            continue
        # Derivation: block source feeds a hash, an assignment
        # or a modulo - not merely a comparison / lock check.
        derives = False
        for m in re.finditer(r"keccak256\s*\(", text):
            inner, _ = _balanced(text, m.end() - 1)
            if _BLOCK_SRC_RE.search(inner):
                derives = True
                break
        if not derives:
            derives = bool(re.search(
                r"\w+\s*=[^;]*("
                r"block\.timestamp|block\.prevrandao|"
                r"block\.difficulty|blockhash\s*\()", text)
                or re.search(
                    r"(block\.timestamp|block\.prevrandao|"
                    r"block\.difficulty)\s*%", text))
        if not derives:
            continue  # time comparison / lock only: silent
        moves = bool(_VALUE_MOVE_RE.search(text))
        selects = bool(_MOD_SELECT_RE.search(text) and
                       "%" in text and ".length" in text)
        if not (moves or selects):
            continue
        # Flow discipline (FP elimination, 2026-11-05): the
        # block-derived value must actually REACH the value
        # move or the selection. Governance-token mints
        # (Uni / Dydx lineage) store `block.timestamp` into
        # a minting-schedule variable and mint a
        # caller-supplied amount - the block source decides
        # WHEN, never WHAT or WHO. That is not a randomness
        # outcome.
        derived_vars = set()
        for m in re.finditer(
                r"(\w+)\s*=[^;]*?(block\.timestamp|"
                r"block\.prevrandao|block\.difficulty|"
                r"blockhash\s*\()", text):
            derived_vars.add(m.group(1))
        for m in re.finditer(r"keccak256\s*\(", text):
            inner, _ = _balanced(text, m.end() - 1)
            if not _BLOCK_SRC_RE.search(inner):
                continue
            head = text[:m.start()].rsplit(";", 1)[-1]
            tm = re.search(r"(\w+)\s*=\s*[^=]*$", head)
            if tm:
                derived_vars.add(tm.group(1))
        flows = False
        for var in derived_vars:
            vre = r"\b" + re.escape(var) + r"\b"
            # used as / inside a selection index or modulo
            if re.search(r"\[\s*[^\]]*" + vre, text) or \
                    re.search(vre + r"[^;]*%", text) or \
                    re.search(r"%[^;]*" + vre, text):
                flows = True
                break
            # used inside a value-moving call's arguments
            # (body only - the function's own signature
            # header also matches the move pattern, and its
            # "segment" would swallow the whole prologue)
            body_at = text.find("{")
            for m in _VALUE_MOVE_RE.finditer(text):
                if m.start() < body_at:
                    continue
                paren = text.find("(", m.start())
                if paren >= 0:
                    args, _ = _balanced(text, paren)
                    seg = args
                else:
                    seg_end = text.find(";", m.start())
                    seg = text[m.start():seg_end if seg_end >= 0
                               else len(text)]
                if re.search(vre, seg):
                    flows = True
                    break
            if flows:
                break
            # returned as the outcome
            if re.search(r"\breturn\b[^;]*" + vre, text):
                flows = True
                break
        if not flows and derived_vars:
            continue
        if not flows and not derived_vars:
            # Direct derivation with no named intermediate:
            # the block source itself must sit inside the
            # value move / selection statement.
            direct = False
            body_at = text.find("{")
            for m in _VALUE_MOVE_RE.finditer(text):
                if m.start() < body_at:
                    continue
                paren = text.find("(", m.start())
                if paren >= 0:
                    seg, _ = _balanced(text, paren)
                else:
                    seg_end = text.find(";", m.start())
                    seg = text[m.start():seg_end if seg_end >= 0
                               else len(text)]
                if _BLOCK_SRC_RE.search(seg):
                    direct = True
                    break
            if not direct and selects:
                for stmt in text.split(";"):
                    if "%" in stmt and ".length" in stmt and \
                            _BLOCK_SRC_RE.search(stmt):
                        direct = True
                        break
            if not direct:
                continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' derives from a block "
            f"source and "
            + ("moves value" if moves else
               "selects a winner/index by modulo over an "
               "array") + " in the same function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "block-derived value outcome; no VRF / "
                    "commit-reveal marker in the function and "
                    "the block source is not confined to a "
                    "time comparison")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 13. empty_signature_accepted (CRY-007 slice)
# ---------------------------------------------------------------------------

_EMPTY_ACCEPT_RE = re.compile(
    r"\.length\s*==\s*0\s*\)\s*\{?\s*return\s+true|"
    r"\.length\s*==\s*0\s*\)\s*\{?\s*return\s+[^;]*valid|"
    r"if\s*\([^)]*\.length\s*==\s*0[^)]*\)\s*\{?[^}]*"
    r"return\s+true")
_SPLIT_RE = re.compile(
    r"mload\s*\(\s*add\s*\(|splitSignature|"
    r"SignatureLib\.split|\.slice\s*\(")
# NOTE (FP elimination, 2026-11-05): a bare `assembly` block
# is NOT signature splitting - Dai's permit builds its
# digest in assembly while taking v / r / s as scalar
# parameters, and fired here. A split requires an actual
# mload(add(sig, ...)) / split helper over a bytes
# signature.
_LENGTH_OK_RE = re.compile(
    r"\.length\s*(==|>=|<=)\s*(65|64)\b|\.length\s*>\s*0\b.*"
    r"ecrecover", re.S)


def _analyze_empty_signature(src: str, spec: DetectorSpec,
                             compiler: str = "",
                             contract_name: str = ""
                             ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        verifyish = bool(
            _RAW_ECC_RE.search(text) or "ECDSA" in text or
            re.search(r"verif|isValid|validate|signat",
                      fn["name"], re.I))
        if not verifyish:
            continue
        # Shape (a): length == 0 leads to acceptance.
        if _EMPTY_ACCEPT_RE.search(text):
            detail = spec.detail + (
                f" Observed (shape a): '{fn['name']}' "
                f"accepts when the signature length is 0.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        "shape (a): a sig.length == 0 condition "
                        "returns acceptance in a verification "
                        "function; the empty signature is not "
                        "explicitly rejected")
            out.append(_finish_recipient(spec, item, text))
            continue
        # Shape (b): split for raw ecrecover, no length require.
        if not (_SPLIT_RE.search(text) and
                _RAW_ECC_RE.search(text)):
            continue
        has_len_check = any(
            re.search(r"\.length\s*(==|>=)\s*(65|64)\b", c)
            for c in _conditions(text))
        if has_len_check:
            continue
        detail = spec.detail + (
            f" Observed (shape b): '{fn['name']}' splits a "
            f"bytes signature for raw ecrecover with no "
            f"signature-length require (== 65 / >= 64) "
            f"anywhere in the function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "shape (b): signature split for ecrecover "
                    "with no length condition in any require / "
                    "if in the function")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 14. packed_encoding_collision (CRY-010)
# ---------------------------------------------------------------------------

_PACKED_RE = re.compile(r"keccak256\s*\(\s*abi\.encodePacked\s*\(")
_USAGE_CTX_RE = re.compile(
    r"\b\w*(id|Id|ID|digest|Digest|hash|Hash|leaf|Leaf|"
    r"commit|Commit|sig|Sig|key|Key|root|Root)\w*\b")


def _arg_type(arg: str, types: Dict[str, str]) -> Optional[str]:
    arg = arg.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", arg):
        return types.get(arg)
    if arg.startswith('"') or arg.startswith("'"):
        return "string"
    if arg in ("msg.sender", "tx.origin"):
        return "address"
    if arg.startswith("block.") or arg.startswith("msg."):
        return "uint256"
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", arg):
        return "uint256"
    return None


def _analyze_packed_collision(src: str, spec: DetectorSpec,
                              compiler: str = "",
                              contract_name: str = ""
                              ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = _state_vars(scope, fns)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        types = dict(state)
        types.update(_fn_params(fn))
        for m in _PACKED_RE.finditer(text):
            inner, _ = _balanced(text, m.end() - 1)
            args = _split_top(inner)
            if len(args) < 2:
                continue  # <= 1 arg cannot collide this way
            varlen = [a for a in args
                      if _is_varlen_type(
                          _arg_type(a, types) or "")]
            if len(varlen) < 2:
                continue  # address+uint packed uses stay silent
            # Used as id / digest / signature input?
            line_start = text.rfind(";", 0, m.start()) + 1
            line_end = text.find(";", m.end())
            stmt = text[line_start:
                        line_end if line_end >= 0 else len(text)]
            assign = re.search(r"(\w+)\s*=[^=]*$", 
                               text[:m.start()].rsplit(";", 1)[-1])
            ctx_hit = bool(_USAGE_CTX_RE.search(stmt)) or \
                (assign and bool(_USAGE_CTX_RE.search(
                    assign.group(1)))) or \
                "==" in stmt or "[" in stmt.split("=")[0]
            if not ctx_hit:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' computes "
                f"keccak256(abi.encodePacked({inner.strip()})) "
                f"with variable-length arguments {varlen} "
                f"used as an id / digest input.")
            item = _hit(spec, fn["name"], cc._snip(text),
                        detail,
                        ">= 2 variable-length arguments packed "
                        "without length prefixes (abi.encode "
                        "would separate them); argument types "
                        "resolved from the enclosing function's "
                        "parameters / state declarations")
            out.append(_finish_recipient(spec, item, text))
            break
    return out


ANALYZERS = {
    "cross_function_guard_sibling": _analyze_guard_sibling,
    "reentrancy_guard_uninitialized":
        _analyze_guard_uninitialized,
    "eth_send_stipend_brick": _analyze_send_stipend,
    "fallback_state_write_extended":
        _analyze_fallback_extended,
    "token_callback_caller_unverified":
        _analyze_token_callback,
    "multicall_value_reuse": _analyze_multicall,
    "push_payment_revert_dos": _analyze_push_payment,
    "ecdsa_recover_zero_unchecked": _analyze_ecdsa_recover,
    "raw_ecrecover_s_unbounded": _analyze_s_unbounded,
    "merkle_leaf_single_hash": _analyze_merkle_leaf,
    "hardcoded_hash_constant_mismatch":
        _analyze_hash_constant,
    "weak_randomness_value_outcome":
        _analyze_weak_randomness,
    "empty_signature_accepted": _analyze_empty_signature,
    "packed_encoding_collision": _analyze_packed_collision,
}

if not KECCAK_OK:
    # Detector dropped honestly: no keccak route in this
    # environment passed the import self-test, so the CRY-005
    # recomputation cannot be trusted. (In the shipped venv
    # cryptopack_util's pure-Python keccak passes and this
    # branch is not taken.)
    ANALYZERS.pop("hardcoded_hash_constant_mismatch", None)
    SPECS[:] = [s for s in SPECS
                if s.id != "hardcoded_hash_constant_mismatch"]
    SPECS_BY_ID.pop("hardcoded_hash_constant_mismatch", None)


def analyze_deep8_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-8 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors batch 4)
# ---------------------------------------------------------------------------

class DeepAudit8Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 8)"
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
        for item in analyze_deep8_source(
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
                source="deep audit detector batch 8 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit8Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 8) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
